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
    struct tee_comm_ch *ree2tee;
    struct tee_comm_ch *tee2ree;
    uint32_t buf_len;
};

static struct comm_ch comm = {0};

static int setup_comm_ch()
{
    seL4_Word sender_badge = 0;
    seL4_MessageInfo_t msg_info = { 0 };

    struct ipc_msg_ch_addr ch_addr = { 0 };
    seL4_Word *msg_data = (seL4_Word *)&ch_addr;

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

    comm.ree2tee = (struct tee_comm_ch *)ch_addr.ree2tee;
    comm.tee2ree = (struct tee_comm_ch *)ch_addr.tee2ree;

    comm.buf_len = ch_addr.len - sizeof(struct tee_comm_ch);

    /* producer initializes channel */
    memset(comm.tee2ree->buf, 0x0, comm.buf_len);
    comm.tee2ree->head = 0;
    comm.tee2ree->tail = 0;

    /* Magic inidicates channel setup is ready. Compiler fence ensures
     * magic writing happens after init */
    COMPILER_MEMORY_RELEASE();
    comm.tee2ree->tee_magic = COMM_MAGIC_TEE;
    comm.ree2tee->tee_magic = COMM_MAGIC_TEE;

    ZF_LOGI("ch: ree2tee [%p], tee2ree [%p]", comm.ree2tee, comm.tee2ree);

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
}