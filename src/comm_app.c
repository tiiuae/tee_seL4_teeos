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
#include <errno.h>

#include <sel4runtime.h>
#include <sel4platsupport/platsupport.h>
#include <sel4utils/process.h>

#include <teeos_common.h>

#include <utils/fence.h>
#include <utils/zf_log.h>

seL4_CPtr ipc_root_ep = 0;

struct comm_ch {
    struct tee_comm_ch ree2tee;
    struct tee_comm_ch tee2ree;
};

static struct comm_ch comm = {0};

static int setup_comm_ch()
{
    seL4_Word sender_badge = 0;
    seL4_MessageInfo_t msg_info = { 0 };

    struct ipc_msg_ch_addr ch_addr = { 0 };
    seL4_Word *msg_data = (seL4_Word *)&ch_addr;

    struct tee_comm_ctrl *ch_ctrl = 0;

    ZF_LOGI("Waiting channel setup..");
    msg_info = seL4_Recv(ipc_root_ep, &sender_badge);

    seL4_Word msg_len = seL4_MessageInfo_get_length(msg_info);
    if (msg_len != IPC_CMD_WORDS(ch_addr)) {
        ZF_LOGF("ipc msg_len: %ld", msg_len);
        return EINVAL;
    }

    for (seL4_Word i = 0; i < msg_len; i++) {
        msg_data[i] = seL4_GetMR(i);
    }

    if (ch_addr.cmd_id != IPC_CMD_CH_ADDR) {
        ZF_LOGF("ipc cmd_id: %p", (void *)ch_addr.cmd_id);
        return EPERM;
    }

    if (ch_addr.ctrl_len < (sizeof(struct tee_comm_ctrl) * 2)) {
        ZF_LOGF("ctrl len: %ld", ch_addr.ctrl_len);
        return ENOBUFS;
    }

    ch_ctrl = (struct tee_comm_ctrl *)ch_addr.ctrl;

    comm.ree2tee.ctrl = &ch_ctrl[COMM_CH_REE2TEE];
    comm.ree2tee.buf_len = ch_addr.ree2tee_len;
    comm.ree2tee.buf = (char *)ch_addr.ree2tee;

    comm.tee2ree.ctrl = &ch_ctrl[COMM_CH_TEE2REE];
    comm.tee2ree.buf_len = ch_addr.tee2ree_len;
    comm.tee2ree.buf = (char *)ch_addr.tee2ree;

    /* writer initializes channel */
    memset(comm.tee2ree.buf, 0x0, comm.tee2ree.buf_len);

    comm.tee2ree.ctrl->head = 0;
    comm.tee2ree.ctrl->tail = 0;

    /* Magic inidicates channel setup is ready. Compiler fence ensures
     * magic writing happens after init */
    COMPILER_MEMORY_RELEASE();
    comm.tee2ree.ctrl->tee_magic = COMM_MAGIC_TEE;
    comm.ree2tee.ctrl->tee_magic = COMM_MAGIC_TEE;

    ZF_LOGI("ch: ree2tee.ctrl [%p], buf [%p]", comm.ree2tee.ctrl,
            comm.ree2tee.buf);

    ZF_LOGI("ch: tee2ree.ctrl [%p], buf [%p]", comm.tee2ree.ctrl,
            comm.tee2ree.buf);

    return 0;
}

static int wait_ree_setup()
{
    uint32_t tee2ree_magic = comm.ree2tee.ctrl->ree_magic;
    uint32_t ree2tee_magic = comm.tee2ree.ctrl->ree_magic;

    ZF_LOGI("waiting REE magic...");
    /* wait until REE writes magic to both channels */
    while (tee2ree_magic != COMM_MAGIC_REE || tee2ree_magic != ree2tee_magic) {
        /* atomic load to prevent compiler optimization with
           while loop comparison */
        tee2ree_magic =
            __atomic_load_n(&comm.tee2ree.ctrl->ree_magic, __ATOMIC_RELAXED);
        ree2tee_magic =
            __atomic_load_n(&comm.ree2tee.ctrl->ree_magic, __ATOMIC_RELAXED);

        seL4_Yield();
    }

    ZF_LOGI("REE comm ready");

    return 0;
}

static int wait_ree_msg()
{
    uint32_t head = comm.ree2tee.ctrl->head;

    ZF_LOGI("waiting value change...");
    while(1) {
        uint32_t new_head = __atomic_load_n(&comm.ree2tee.ctrl->head, __ATOMIC_RELAXED);
        if (head != new_head) {
            head = new_head;
            comm.tee2ree.ctrl->head++;
            ZF_LOGI("new_head: 0x%x", new_head);
        }
        seL4_Yield();
    }
    return 0;
}

int main(int argc, char **argv)
{
    int error = -1;

    ZF_LOGI("%s", CONFIG_TEE_COMM_APP_NAME);
    seL4_DebugNameThread(SEL4UTILS_TCB_SLOT, CONFIG_TEE_COMM_APP_NAME);

    if (argc != 1) {
        ZF_LOGF("Invalid arg count: %d", argc);
        return EINVAL;
    }

    ipc_root_ep = (seL4_CPtr)atol(argv[0]);
    if (ipc_root_ep == 0) {
        ZF_LOGF("Invalid endpoint");
        return EFAULT;
    }

    ZF_LOGI("ipc_root_ep: %p", (void *)ipc_root_ep);

    /* Wait shared memory config from rootserver and init tee2ree channel */
    error = setup_comm_ch(ipc_root_ep);
    if (error) {
        return error;
    }

    /* Wait linux to init ree2tee channel */
    error = wait_ree_setup();
    if (error) {
        return error;
    }

    error = wait_ree_msg();

    return error;
}