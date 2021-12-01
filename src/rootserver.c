/*
 * Copyright 2021, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */


#include <teeos/gen_config.h>

#include <regex.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <limits.h>
#include <stdint.h>

#include <sel4runtime.h>

#include <allocman/vka.h>
#include <sel4utils/vspace.h>
#include <sel4platsupport/platsupport.h>
#include <simple/simple.h>
#include <simple-default/simple-default.h>
#include <allocman/bootstrap.h>
#include <sel4platsupport/io.h>
#include <platsupport/fdt.h>
#include <sel4utils/thread_config.h>
#include <sel4utils/process_config.h>
#include <sel4utils/process.h>

#include <utils/zf_log.h>

#include <teeos_common.h>

#define ALLOCATOR_STATIC_POOL_SIZE      ((1 << seL4_PageBits) * 20)
#define ALLOCATOR_VIRTUAL_POOL_SIZE     ((1 << seL4_PageBits) * 100)

#define MEM_CACHED                      1

#define FDT_PATH_CTRL                   "/teeos_comm/ctrl"
#define FDT_PATH_REE2TEE                "/teeos_comm/ree2tee"
#define FDT_PATH_TEE2REE                "/teeos_comm/tee2ree"

#define RESUME_PROCESS                  1

#define TEE_COMM_APP_BADGE              0x80
#define APP2_BADGE                      0x81

struct fdt_config {
    uintptr_t paddr;
    uint32_t len;
    void *root_addr;
    void *app_addr;
};

struct app_env {
    sel4utils_process_t app_proc;
    seL4_CPtr root_ep;
    seL4_Word badge;
    seL4_CPtr app_ep1;
};

struct root_env {
    vka_t vka;
    vspace_t vspace;
    simple_t simple;

    sel4utils_alloc_data_t vm_data;

    char allocator_mem_pool[ALLOCATOR_STATIC_POOL_SIZE];

    ps_io_ops_t ops;

    struct fdt_config ch_ctrl;
    struct fdt_config comm_ch[COMM_CH_COUNT];

    seL4_CPtr root_ep;
    seL4_CPtr inter_app_ep1;

    struct app_env comm_app;
    struct app_env app_2;
};
static struct root_env root_ctx = { 0 };

struct fdt_cb_token {
    struct root_env *ctx;
    const char *fdt_path;
    struct fdt_config *config;
};

static void root_exit(int code)
{
    ZF_LOGI("%d", code);
    seL4_TCB_Suspend(seL4_CapInitThreadTCB);
}

static int create_eps(struct root_env *ctx)
{
    int err = -1;

    /* rootserver endpoint for communication */
    vka_object_t ep = { 0 };

    err = vka_alloc_endpoint(&ctx->vka, &ep);
    if (err) {
        ZF_LOGF("vka_alloc_endpoint: %d", err);
        return err;
    }

    ctx->root_ep = ep.cptr;

    /* endpoint for inter app communication */
    err = vka_alloc_endpoint(&ctx->vka, &ep);
    if (err) {
        ZF_LOGF("vka_alloc_endpoint: %d", err);
        return err;
    }

    ctx->inter_app_ep1 = ep.cptr;

    return err;
}

static int mint_ep_to_process(struct root_env *root_ctx, seL4_CPtr root_ep,
                              struct app_env *app, seL4_CPtr *app_ep)
{
    cspacepath_t ep_path;
    vka_cspace_make_path(&root_ctx->vka, root_ep, &ep_path);

    /* create badged endpoint for app process */
    *app_ep = sel4utils_mint_cap_to_process(&app->app_proc, ep_path,
                                            seL4_AllRights, app->badge);

    if (!*app_ep) {
        ZF_LOGF("app_ep == NULL");
        return EBADSLT;
    }

    return 0;
}

static int lauch_app(struct root_env *root_ctx, struct app_env *app_ctx,
                    const char *image_name, seL4_Word app_badge)
{
    int err = -1;

    sel4utils_process_t *new_process = &app_ctx->app_proc;

    sel4utils_process_config_t config = process_config_default_simple(
        &root_ctx->simple, image_name, seL4_MaxPrio);

    config = process_config_auth(config, simple_get_tcb(&root_ctx->simple));
    config = process_config_priority(config, seL4_MaxPrio);
    err = sel4utils_configure_process_custom(new_process, &root_ctx->vka,
                                             &root_ctx->vspace, config);
    if (err) {
        ZF_LOGF("sel4utils_configure_process_custom: %d", err);
        return err;
    }

    NAME_THREAD(new_process->thread.tcb.cptr, image_name);

    app_ctx->badge = app_badge;

    /* Copy rootserver IPC caps to process */
    err = mint_ep_to_process(root_ctx,
                             root_ctx->root_ep,
                             app_ctx,
                             &app_ctx->root_ep);
    if (err) {
        return err;
    }

    /* Copy inter app IPC caps to process */
    err = mint_ep_to_process(root_ctx,
                             root_ctx->inter_app_ep1,
                             app_ctx,
                             &app_ctx->app_ep1);
    if (err) {
        return err;
    }

    #define APP_ARGC 1 /* local #define used for array initialization */
    char string_args[APP_ARGC][WORD_STRING_SIZE] = { 0 };
    char *app_argv[APP_ARGC] = { 0 };

    /* provide badged comm endpoint as arg */
    sel4utils_create_word_args(string_args, app_argv, APP_ARGC,
                               app_ctx->root_ep);

    err = sel4utils_spawn_process_v(new_process,
                                    &root_ctx->vka,
                                    &root_ctx->vspace,
                                    APP_ARGC, app_argv,
                                    RESUME_PROCESS);
    if (err) {
        ZF_LOGF("sel4utils_spawn_process_v: %d", err);
        return err;
    }

    return err;
}

static int fdt_reg_cb(pmem_region_t pmem, unsigned curr_num, size_t num_regs, void *token)
{
    struct fdt_cb_token *fdt_token = (struct fdt_cb_token *)token;
    
    if (curr_num != 0) {
        ZF_LOGF("invalid reg: %d", curr_num);
        return EINVAL;
    }

    fdt_token->config->paddr = pmem.base_addr;
    fdt_token->config->len = pmem.length;

    return 0;
}

static int get_ch_fdt(struct fdt_cb_token *token)
{
    int err = -1;
    ps_fdt_cookie_t *fdt_cookie = NULL;

    /* get devicetree path */
    err = ps_fdt_read_path(&token->ctx->ops.io_fdt,
                            &token->ctx->ops.malloc_ops,
                            token->fdt_path, &fdt_cookie);
    if (err) {
        ZF_LOGF("ps_fdt_read_path: %d, %s", err, token->fdt_path);
        return err;
    }

    /* fdt_reg_cb is called for register entry */
    err = ps_fdt_walk_registers(&token->ctx->ops.io_fdt, fdt_cookie, fdt_reg_cb, token);
    if (err) {
        ZF_LOGF("ps_fdt_walk_registers: %d", err);
        return err;
    }

    ps_fdt_cleanup_cookie(&token->ctx->ops.malloc_ops, fdt_cookie);

    return err;
}

static int get_teeos_comm_ch(struct root_env *ctx, struct fdt_cb_token *token)
{
    int err = -1;
    struct fdt_config *ch = token->config;
    int page_count = 0;
    sel4utils_process_t *app_proc = &ctx->comm_app.app_proc;

    /* get config from devicetree */
    err = get_ch_fdt(token);
    if (err) {
        return err;
    }

    if (!ch->paddr || ch->len == 0) {
        ZF_LOGF("invalid config paddr: %p, len %d", (void*)ch->paddr, ch->len);
        return ENODEV;
    }

    /* map physical address to rootserver vspace*/
    ch->root_addr = ps_io_map(&ctx->ops.io_mapper, ch->paddr, ch->len,
                                MEM_CACHED, PS_MEM_NORMAL);
    if (!ch->root_addr) {
        ZF_LOGF("ps_io_map failed: %p / %d", (void *)ch->paddr, ch->len);
        return EIO;
    }

    /* share mapped channel to app vspace */
    page_count = BYTES_TO_SIZE_BITS_PAGES(ch->len, seL4_PageBits);
    ch->app_addr = vspace_share_mem(&ctx->vspace,
                                    &app_proc->vspace,
                                    ch->root_addr,
                                    page_count,
                                    seL4_PageBits,
                                    seL4_AllRights,
                                    MEM_CACHED);

    if (!ch->app_addr) {
        ZF_LOGF("vspace_share_mem == NULL");
        return EFAULT;
    }

    return err;
}

static int map_ree_comm_ch(struct root_env *ctx)
{
    int err = -1;
    struct fdt_cb_token fdt_token = {
        .ctx = ctx,
    };

    /* Separate shared area reserved for ring buffer status data */
    fdt_token.fdt_path = FDT_PATH_CTRL;
    fdt_token.config = &ctx->ch_ctrl;
    err = get_teeos_comm_ch(ctx, &fdt_token);
    if (err) {
        return err;
    }

    ZF_LOGI("ctrl    %p - %p, vaddr %p", (void *)fdt_token.config->paddr,
            (void *)(fdt_token.config->paddr + fdt_token.config->len - 1),
            (void *)fdt_token.config->root_addr);

    /* REE -> TEE */
    fdt_token.fdt_path = FDT_PATH_REE2TEE;
    fdt_token.config = &ctx->comm_ch[COMM_CH_REE2TEE];
    err = get_teeos_comm_ch(ctx, &fdt_token);
    if (err) {
        return err;
    }

    ZF_LOGI("ree2tee %p - %p, vaddr %p", (void *)fdt_token.config->paddr,
            (void *)(fdt_token.config->paddr + fdt_token.config->len - 1),
            (void *)fdt_token.config->root_addr);

    /* TEE -> REE */
    fdt_token.fdt_path = FDT_PATH_TEE2REE;
    fdt_token.config = &ctx->comm_ch[COMM_CH_TEE2REE];
    err = get_teeos_comm_ch(ctx, &fdt_token);
    if (err) {
        return err;
    }

    ZF_LOGI("tee2ree %p - %p, vaddr %p", (void *)fdt_token.config->paddr,
            (void *)(fdt_token.config->paddr + fdt_token.config->len - 1),
            (void *)fdt_token.config->root_addr);

    return err;
}

static void send_comm_ch_addr(struct root_env *ctx)
{
    struct ipc_msg_ch_addr ch_addr = {
        .cmd_id = IPC_CMD_CH_ADDR_RESP,
        .ctrl = (uintptr_t)ctx->ch_ctrl.app_addr,
        .ctrl_len = ctx->ch_ctrl.len,
        .ree2tee = (uintptr_t)ctx->comm_ch[COMM_CH_REE2TEE].app_addr,
        .ree2tee_len = ctx->comm_ch[COMM_CH_REE2TEE].len,
        .tee2ree = (uintptr_t)ctx->comm_ch[COMM_CH_TEE2REE].app_addr,
        .tee2ree_len = ctx->comm_ch[COMM_CH_REE2TEE].len,
    };

    const uint32_t msg_words = IPC_CMD_WORDS(ch_addr);

    seL4_Word *msg_data = (seL4_Word *)&ch_addr;

    seL4_MessageInfo_t msg_info = seL4_MessageInfo_new(0, 0, 0, msg_words);
    for (uint32_t i = 0; i < msg_words; i++) {
        seL4_SetMR(i, msg_data[i]);
    }

    ZF_LOGI("Send IPC_CMD_CH_ADDR_RESP");
    seL4_Reply(msg_info);
}

static void send_inter_app_ep(struct root_env *ctx, seL4_Word sender)
{
    struct ipc_msg_app_ep ep_msg = {
        .cmd_id = IPC_CMD_APP_EP_RESP,
    };
    const uint32_t MSG_WORDS = IPC_CMD_WORDS(ep_msg);

    seL4_Word *msg_data = (seL4_Word *)&ep_msg;

    switch (sender) {
    case TEE_COMM_APP_BADGE:
        ep_msg.app_ep = ctx->comm_app.app_ep1;
        break;
    case APP2_BADGE:
        ep_msg.app_ep = ctx->app_2.app_ep1;
        break;
    /* Do nothing for unknown senders */
    default:
        ZF_LOGE("unknown sender: 0x%lx", sender);
    }

    seL4_MessageInfo_t msg_info = seL4_MessageInfo_new(0, 0, 0, MSG_WORDS);
    for (uint32_t i = 0; i < MSG_WORDS; i++) {
        seL4_SetMR(i, msg_data[i]);
    }

    ZF_LOGI("Send IPC_CMD_APP_EP_RESP");
    seL4_Reply(msg_info);
}

static void process_ipc_msg(struct root_env *ctx, seL4_Word sender, seL4_Word msg_len)
{
    seL4_Word ipc_cmd_id = 0;

    ipc_cmd_id = seL4_GetMR(0);

    switch (ipc_cmd_id) {
    case IPC_CMD_CH_ADDR_REQ:
        send_comm_ch_addr(ctx);
        break;
    case IPC_CMD_APP_EP_REQ:
        send_inter_app_ep(ctx, sender);
        break;
    default:
        ZF_LOGE("unknown cmd id: (0x%lx) 0x%lx", sender, ipc_cmd_id);
        break;
    }
}

static void recv_ipc_loop(struct root_env *ctx)
{
	seL4_Word sender = 0;
    seL4_MessageInfo_t msg_info = { 0 };
    seL4_Word msg_len = 0;

    while (1) {
        msg_info = seL4_Recv(ctx->root_ep, &sender);
        msg_len = seL4_MessageInfo_get_length(msg_info);

        /* Discard empty messages */
        if (msg_len < 1) {
            ZF_LOGE("empty msg: 0x%lx", sender);
            continue;
        }

        process_ipc_msg(ctx, sender, msg_len);
    }
}

int main(void)
{
    int err = -1;
    allocman_t *allocman = NULL;
    reservation_t virtual_reservation = {0};
    void *vstart = NULL;
    struct root_env *ctx = &root_ctx;

    sel4runtime_set_exit(root_exit);

    seL4_DebugNameThread(seL4_CapInitThreadTCB, "teeos_root");

    fflush(stdout);

    seL4_BootInfo *info = platsupport_get_bootinfo();

    simple_default_init_bootinfo(&ctx->simple, info);

    allocman = bootstrap_use_current_simple(&ctx->simple,
                                            ALLOCATOR_STATIC_POOL_SIZE,
                                            ctx->allocator_mem_pool);
    if (allocman == NULL) {
        ZF_LOGF("allocman == NULL");
        return EFAULT;
    }

    allocman_make_vka(&ctx->vka, allocman);

    err = sel4utils_bootstrap_vspace_with_bootinfo_leaky(
                                                &ctx->vspace,
                                                &ctx->vm_data,
                                                simple_get_pd(&ctx->simple),
                                                &ctx->vka,
                                                platsupport_get_bootinfo());
    if (err) {
        ZF_LOGF("sel4utils_bootstrap_vspace_with_bootinfo_leaky: %d", err);
        return err;
    }

    virtual_reservation = vspace_reserve_range(&ctx->vspace,
                                               ALLOCATOR_VIRTUAL_POOL_SIZE,
                                               seL4_AllRights,
                                               1,
                                               &vstart);
    if (virtual_reservation.res == 0) {
        ZF_LOGF("virtual_reservation == NULL");
        return EFAULT;
    }

    bootstrap_configure_virtual_pool(allocman,
                                     vstart, 
                                     ALLOCATOR_VIRTUAL_POOL_SIZE,
                                     simple_get_pd(&ctx->simple));

    err = sel4platsupport_new_io_ops(&ctx->vspace, &ctx->vka, &ctx->simple,
                                       &ctx->ops);
    if (err) {
        ZF_LOGF("sel4platsupport_new_io_ops: %d", err);
        return err;
    }

    err = platsupport_serial_setup_simple(&ctx->vspace, &ctx->simple, &ctx->vka);
    if (err) {
        ZF_LOGF("platsupport_serial_setup_simple: %d", err);
        return err;
    }

    simple_print(&ctx->simple);

    /* Create endpoints for app <-> rootserver and app <-> app IPC */
    err = create_eps(ctx);
    if (err) {
        return err;
    }

    /* Create, configure & launch app processes */
    err = lauch_app(ctx, &ctx->comm_app, CONFIG_TEE_COMM_APP_NAME, TEE_COMM_APP_BADGE);
    if (err) {
        return err;
    }

    err = lauch_app(ctx, &ctx->app_2, CONFIG_APP2_NAME, APP2_BADGE);
    if (err) {
        return err;
    }

    /* Map REE communication channels */
    err = map_ree_comm_ch(ctx);
    if (err) {
        return err;
    }

    /* IPC process loop */
    recv_ipc_loop(ctx);

    return 0;
}