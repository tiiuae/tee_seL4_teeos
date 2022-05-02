/*
 * Copyright 2021, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sel4_teeos/gen_config.h>

#include <regex.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <stdint.h>

#include <sel4runtime.h>

#include <teeos_common.h>
#include <sys_ctl_service.h>
#include <ree_tee_msg.h>
#include <teeos_service.h>
#include <pkcs11_service.h>

/* Local log level */
#define ZF_LOG_LEVEL    ZF_LOG_ERROR
#include <utils/util.h>
#include <utils/zf_log.h>

#include <sel4utils/process.h>

#include "sel4_crashlog.h"
#include "sel4_optee_serializer.h"

struct sel4_ipc_call_data {
    uint32_t len;
    seL4_Word *buf;
};

#define SET_IPC_CMD_TYPE(ipc_data_ptr, cmd) \
    do {                                    \
        (ipc_data_ptr)->len = 1;            \
        (ipc_data_ptr)->buf[0] = cmd;       \
    } while (0)

#define SET_IPC_SYS_FAIL(ipc_data_ptr) SET_IPC_CMD_TYPE(ipc_data_ptr, IPC_CMD_SYS_FAIL)

static seL4_CPtr ipc_root_ep = 0;
static seL4_CPtr ipc_app_ep1 = 0;

static void *app_shared_memory;
static uint32_t shared_memory_size;

static struct crashlog_ctx crashlog = { 0 };

uint64_t sel4_debug_config;
static int seed_counter;

static int setup_crashlog(void)
{
    int error = -1;

    seL4_Word ipc_req = IPC_CMD_CRASHLOG_REQ;

    struct ipc_msg_crash_log_addr ipc_resp = { 0 };

    ZF_LOGI("seL4_Call: IPC_CMD_CRASHLOG_REQ");

    error = ipc_msg_call(ipc_root_ep,
                         SINGLE_WORD_MSG,
                         &ipc_req,
                         IPC_CMD_CRASHLOG_RESP,
                         IPC_CMD_WORDS(ipc_resp),
                         (seL4_Word *)&ipc_resp);

    if (error) {
        ZF_LOGF("error ipc_msg_call: %d", error);
        return error;
    }

    sel4_crashlog_setup_cb(&crashlog, (void *)ipc_resp.crashlog);

    ZF_LOGI("crashlog setup");

    return 0;
}

static int setup_sys_ctl_io(void)
{
    uint32_t *sys_reg_base;
    uint32_t *mbox_base;
    uint32_t *msg_int_reg;
    int error;

    seL4_Word ipc_req = IPC_CMD_SYS_CTL_ADDR_REQ;
    struct ipc_msg_cys_ctl_addr ipc_resp = { 0 };

    ZF_LOGI("IPC_CMD_SYS_CTL_ADDR_REQ");

    error = ipc_msg_call(ipc_root_ep,
                         SINGLE_WORD_MSG,
                         &ipc_req,
                         IPC_CMD_SYS_CTL_ADDR_RESP,
                         IPC_CMD_WORDS(ipc_resp),
                         (seL4_Word *)&ipc_resp);

    if (error) {
        ZF_LOGF("ERROR ipc_msg_call: %d", error);
        return error;
    }

    sys_reg_base = (uint32_t *)ipc_resp.reg_base;
    mbox_base = (uint32_t *)ipc_resp.mbox_base;
    msg_int_reg = (uint32_t *)ipc_resp.msg_int_reg;
    app_shared_memory = (void*)ipc_resp.shared_memory;
    shared_memory_size = ipc_resp.shared_len;

    ZF_LOGI("System controll addresses: Regbase %p  Mbox base %p Msg_int_reg %p ", sys_reg_base, mbox_base, msg_int_reg);
    set_sys_ctl_address(sys_reg_base, mbox_base, msg_int_reg);

    return 0;
}

static int setup_app_ep(void)
{
    int error = -1;

    seL4_Word ipc_req = IPC_CMD_APP_EP_REQ;
    /* IPC response */
    struct ipc_msg_app_ep ipc_resp = { 0 };

    ZF_LOGI("seL4_Call: IPC_CMD_APP_EP_REQ");

    error = ipc_msg_call(ipc_root_ep,
                         SINGLE_WORD_MSG,
                         &ipc_req,
                         IPC_CMD_APP_EP_RESP,
                         IPC_CMD_WORDS(ipc_resp),
                         (seL4_Word *)&ipc_resp);

    if (error) {
        ZF_LOGF("ERROR ipc_msg_call: %d", error);
        return error;
    }

    ipc_app_ep1 = ipc_resp.app_ep;

    ZF_LOGI("ipc_app_ep1: 0x%lx", ipc_app_ep1);

    return 0;
}

static void handle_service_requests(void)
{
    seL4_MessageInfo_t msg_info = {0};
    seL4_Word msg_len = 0;
    seL4_Word sender_badge = 0;
    int ret;

    /* malloc size in bytes */
    seL4_Word *sel4_ipc_buf = malloc(seL4_MsgMaxLength * sizeof(seL4_Word) * 2);

    struct sel4_ipc_call_data sel4_ipc_recv = {
        .len = 0,
        .buf = sel4_ipc_buf,
    };

    struct sel4_ipc_call_data sel4_ipc_reply = {
        .len = 0,
        .buf = sel4_ipc_buf + seL4_MsgMaxLength, /* offset of seL4_Words */
    };

    if (!sel4_ipc_buf) {
        ZF_LOGF("Out of memory");
        return;
    }

    while(1)
    {
        seed_counter++;
        /* Reseed rng periodically */
        if (seed_counter % 10 == 0) {
            ret = teeos_reseed_fortuna_rng();
            ZF_LOGI("RNG Reseed return value was %d", ret);
        }
        ZF_LOGI("Wait msg from comm app...");
        msg_info = seL4_Recv(ipc_app_ep1, &sender_badge);
        sel4_ipc_recv.len = seL4_MessageInfo_get_length(msg_info);

        if (sel4_ipc_recv.len == 0) {
            ZF_LOGE("ERROR empty ipc");

            /* Force error reply */
            sel4_ipc_recv.buf[0] = IPC_CMD_EMPTY;
        }

        for (uint32_t i = 0; i < sel4_ipc_recv.len; i++) {
            sel4_ipc_recv.buf[i] = seL4_GetMR(i);
        }

        ZF_LOGI("msg from 0x%lx (%ld) 0x%lx", sender_badge, msg_len, sel4_ipc_recv.buf[0]);

        switch (sel4_ipc_recv.buf[0])
        {
            case IPC_CMD_CONFIG_REQ:
            {
                struct ree_tee_config_cmd *cmd = (struct ree_tee_config_cmd*)app_shared_memory;

                /* Current config in reply */
                if (cmd->debug_config & (1UL << 63)) {
                    cmd->debug_config = sel4_debug_config;
                } else {
                    sel4_debug_config = cmd->debug_config;
                }
                SET_IPC_CMD_TYPE(&sel4_ipc_reply, IPC_CMD_CONFIG_RESP);
                ZF_LOGI("\n DEBUG config received 0x%lx", cmd->debug_config);
            }
            break;
            case IPC_CMD_SYS_CTL_RNG_REQ:
            {
                ZF_LOGI("RNG request");
                memset(app_shared_memory,0,32);
                int err = nonce_service(app_shared_memory);
                if (!err) {
                    SET_IPC_CMD_TYPE(&sel4_ipc_reply, IPC_CMD_SYS_CTL_RNG_RESP);
                }
                else {
                    ZF_LOGI("RNG service failed");
                    SET_IPC_SYS_FAIL(&sel4_ipc_reply);
                }
            }
            break;

            case IPC_CMD_SYS_CTL_DEVICEID_REQ:
            {
                ZF_LOGI("device id request");
                memset(app_shared_memory, 0, MSS_SYS_SERIAL_NUMBER_RESP_LEN);

                int err = get_serial_number(app_shared_memory);
                if (!err) {
                    SET_IPC_CMD_TYPE(&sel4_ipc_reply, IPC_CMD_SYS_CTL_DEVICEID_RESP);
                }
                else {
                    ZF_LOGI("device id service failed");
                    SET_IPC_SYS_FAIL(&sel4_ipc_reply);
                }
            }
            break;
            case IPC_CMD_OPTEE_REQ:
            {
                ZF_LOGI("OPTEE cmd");

                struct ipc_msg_gen_payload *sel4_req =
                    (struct ipc_msg_gen_payload *)sel4_ipc_recv.buf;

                struct ipc_msg_gen_payload *sel4_resp =
                    (struct ipc_msg_gen_payload *)sel4_ipc_reply.buf;

                uint32_t resp_len = 0;

                int err = sel4_optee_handle_cmd(app_shared_memory,
                                                sel4_req->payload_size,
                                                &resp_len,
                                                shared_memory_size);

                if (err) {
                    ZF_LOGE("OPTEE cmd failed %d ", err);
                    SET_IPC_SYS_FAIL(&sel4_ipc_reply);
                    break;
                }

                sel4_resp->cmd_id = IPC_CMD_OPTEE_RESP;
                sel4_resp->payload_size = resp_len;

                sel4_ipc_reply.len = IPC_CMD_WORDS(struct ipc_msg_gen_payload);
            }
            break;
            case IPC_CMD_OPTEE_INIT_REQ:
            {
                ZF_LOGI("OPTEE init");

                int err = teeos_init_optee();
                if (!err) {
                    SET_IPC_CMD_TYPE(&sel4_ipc_reply, IPC_CMD_OPTEE_INIT_RESP);
                }
                else {
                    ZF_LOGI("optee init failed");
                    SET_IPC_SYS_FAIL(&sel4_ipc_reply);
                }
            }
            break;
            case IPC_CMD_OPTEE_EXPORT_REQ:
            {
                ZF_LOGI("OPTEE export storage");

                struct ipc_msg_gen_payload *sel4_resp =
                    (struct ipc_msg_gen_payload *)sel4_ipc_reply.buf;

                struct ree_tee_optee_storage_bin *storage =
                    (struct ree_tee_optee_storage_bin*) app_shared_memory;

                uint32_t storage_len = 0;
                uint32_t export_len = 0;
                uint32_t max_size = shared_memory_size - sizeof(struct ree_tee_optee_storage_bin);
                max_size = max_size - max_size % 16;

                int err = teeos_optee_export_storage(storage->pos,
                                                     &storage_len,
                                                     storage->payload,
                                                     max_size,
                                                     &export_len);
                if (err) {
                    ZF_LOGE("OPTEE export storage %d ", err);
                    SET_IPC_SYS_FAIL(&sel4_ipc_reply);
                    break;
                }

                storage->payload_len = export_len;
                storage->storage_len = storage_len;

                sel4_resp->cmd_id = IPC_CMD_OPTEE_EXPORT_RESP;
                sel4_resp->payload_size =
                    sizeof(struct ree_tee_optee_storage_bin) + export_len;

                sel4_ipc_reply.len = IPC_CMD_WORDS(struct ipc_msg_gen_payload);
            }
            break;
            case IPC_CMD_OPTEE_IMPORT_REQ:
            {
                struct ipc_msg_gen_payload *sel4_resp =
                    (struct ipc_msg_gen_payload *)sel4_ipc_reply.buf;

                struct ree_tee_optee_storage_bin *import =
                    (struct ree_tee_optee_storage_bin*) app_shared_memory;

                uint32_t max_size = shared_memory_size - sizeof(struct ree_tee_optee_storage_bin);
                max_size = max_size - max_size % 16;

                if (import->payload_len > max_size) {
                    ZF_LOGE("Invalid payload length: %d", import->payload_len);
                    SET_IPC_SYS_FAIL(&sel4_ipc_reply);
                    break;
                }
                int err = teeos_optee_import_storage(import->payload,
                                                     import->payload_len,
                                                     import->storage_len);
                if (err) {
                    ZF_LOGE("OPTEE import storage %d ", err);
                    SET_IPC_SYS_FAIL(&sel4_ipc_reply);
                    break;
                }

                sel4_resp->cmd_id = IPC_CMD_OPTEE_IMPORT_RESP;
                sel4_resp->payload_size = 0; /* comm_app requires ipc_msg_gen_payload */

                sel4_ipc_reply.len = IPC_CMD_WORDS(struct ipc_msg_gen_payload);

            }
            break;
            default:
                ZF_LOGE("Unsupported message 0x%lx", sel4_ipc_recv.buf[0]);
                SET_IPC_CMD_TYPE(&sel4_ipc_reply, IPC_CMD_UNKNOWN);
                break;
        }


        msg_info = seL4_MessageInfo_new(0, 0, 0, sel4_ipc_reply.len);

        for (uint32_t i = 0; i < sel4_ipc_reply.len; i++) {
            seL4_SetMR(i, sel4_ipc_reply.buf[i]);
        }

        seL4_Reply(msg_info);
    }
}

int main(int argc, char **argv)
{
    int error = -1;

    ZF_LOGI("%s", CONFIG_SYS_APP_NAME);
    seL4_DebugNameThread(SEL4UTILS_TCB_SLOT, CONFIG_SYS_APP_NAME);

    if (argc != 1) {
        ZF_LOGF("Invalid arg count: %d", argc);
        return -EINVAL;
    }

    ipc_root_ep = (seL4_CPtr)atol(argv[0]);
    if (ipc_root_ep == 0) {
        ZF_LOGF("Invalid root endpoint");
        return -EFAULT;
    }

    /* Wait crashlog config from rootserver */
    error = setup_crashlog();
    if (error) {
        return error;
    }

    error = setup_sys_ctl_io();
    if (error) {
        return error;
    }

    error = teeos_init_crypto();
    if (error) {
        return error;
    }

    ZF_LOGI("ipc_root_ep:    %p", (void *)ipc_root_ep);

    error = setup_app_ep();
    if (error) {
        return error;
    }

    /* Ping-pong IPC with comm app */
    seL4_MessageInfo_t msg_info = { 0 };
    seL4_Word msg_len = 0;
    seL4_Word msg_data = 0;

    ZF_LOGI("Send msg to comm app...");
    msg_info = seL4_MessageInfo_new(0, 0, 0, 1);

    seL4_SetMR(0, 1);

    msg_info = seL4_Call(ipc_app_ep1, msg_info);

    msg_len = seL4_MessageInfo_get_length(msg_info);
    if (msg_len > 0) {
        msg_data = seL4_GetMR(0);
    }

    ZF_LOGI("comm app resp (%ld) 0x%lx", msg_len, msg_data);

    handle_service_requests();
    return error;
}