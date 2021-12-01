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

seL4_CPtr ipc_app_ep1 = 0;

uint32_t *sys_reg_base;
uint32_t *mbox_base;
uint32_t *msg_int_reg;


static int setup_sys_ctl_io(void)
{
    seL4_Word sender_badge = 0;
    seL4_MessageInfo_t msg_info = { 0 };
    int error;

    struct ipc_msg_cys_ctl_addr ipc_resp = { 0 };
    const uint32_t RESP_WORDS = IPC_CMD_WORDS(ipc_resp);
    seL4_Word *msg_data = (seL4_Word *)&ipc_resp;

    ZF_LOGI("IPC_CMD_SYS_CTL_ADDR_REQ");

    error = ipc_msg_call(IPC_CMD_SYS_CTL_ADDR_REQ,
                         ipc_root_ep,
                         RESP_WORDS,
                         msg_data);

    if (error)
        return error;

    if (ipc_resp.cmd_id != IPC_CMD_SYS_CTL_ADDR_RESP) {
        ZF_LOGF("ipc cmd_id: 0x%lx", ipc_resp.cmd_id);
        return -EPERM;
    }

    sys_reg_base = (uint32_t *)ipc_resp.reg_base;
    mbox_base = (uint32_t *)ipc_resp.mbox_base;
    msg_int_reg = (uint32_t *)ipc_resp.msg_int_reg;

    ZF_LOGI("System controll addresses: Regbase %p  Mbox base %p Msg_int_reg %p ", sys_reg_base, mbox_base, msg_int_reg);


    return 0;
}

static int setup_app_ep(void)
{
    int error = -1;

    /* IPC response */
    struct ipc_msg_app_ep ipc_resp = { 0 };
    seL4_Word *msg_data = (seL4_Word *)&ipc_resp;

    ZF_LOGI("seL4_Call: IPC_CMD_APP_EP_REQ");

    error = ipc_msg_call(IPC_CMD_APP_EP_REQ,
                         ipc_root_ep,
                         IPC_CMD_WORDS(ipc_resp),
                         msg_data);

    if (error) {
        return error;
    }

    if (ipc_resp.cmd_id != IPC_CMD_APP_EP_RESP) {
        ZF_LOGF("ipc cmd_id: 0x%lx", ipc_resp.cmd_id);
        return -EPERM;
    }

    ipc_app_ep1 = ipc_resp.app_ep;

    ZF_LOGI("ipc_app_ep1: 0x%lx", ipc_app_ep1);

    return 0;
}

int main(int argc, char **argv)
{
    int error = -1;

    ZF_LOGI("%s", CONFIG_APP2_NAME);
    seL4_DebugNameThread(SEL4UTILS_TCB_SLOT, CONFIG_APP2_NAME);

    if (argc != 1) {
        ZF_LOGF("Invalid arg count: %d", argc);
        return -EINVAL;
    }

    ipc_root_ep = (seL4_CPtr)atol(argv[0]);
    if (ipc_root_ep == 0) {
        ZF_LOGF("Invalid root endpoint");
        return -EFAULT;
    }

    error = setup_sys_ctl_io();
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

    return error;
}