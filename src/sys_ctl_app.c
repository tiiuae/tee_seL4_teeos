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
#include <sys_ctl_service.h>

#include <utils/fence.h>
#include <utils/zf_log.h>

seL4_CPtr ipc_root_ep = 0;

seL4_CPtr ipc_app_ep1 = 0;


static int setup_sys_ctl_io(void)
{    
    uint32_t *sys_reg_base;
    uint32_t *mbox_base;
    uint32_t *msg_int_reg;
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
    set_sys_ctl_address(sys_reg_base, mbox_base, msg_int_reg);

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


/*
 * Demo applications to demonstrate system controller services
 *
 */
void Print_random_number(void)
{
    uint8_t random[32];

    if (nonce_service(random))
    {
        ZF_LOGI( "Couldn't read Random Number");
    }

    printf("256 bit random number: \n");
    for(int i = 0; i < 32; i++)
    {
        printf("%2.2x ", random[i]);
    }
    printf("\n");

}



void Device_Serial_Number_Print(void)
{
 uint8_t serial_num_buffer[50];

    memset(serial_num_buffer, 0, ARRAY_SIZE(serial_num_buffer));
    if (0 == get_serial_number(serial_num_buffer))
    {
        printf( "Serial Number: \n" ); // move to boards...
        for (int i = 0; i < (int)ARRAY_SIZE(serial_num_buffer); i++)
        {
            printf("%02x", serial_num_buffer[i]);
        }
        printf("\n");

    }
    else
    {
        ZF_LOGI( "Couldn't read Serial Number");
    }

}

void puf_demo(uint8_t opcode)
{
    
    uint8_t random_input[32] = {0};
    uint8_t response[32] = {0};
    int i, status;
    //generate random bytes
    nonce_service(random_input);
    for (i = 0; i < 16 ; i++)
    {
        printf("%2.2x ", random_input[i]);
    }
    

    status = puf_emulation_service(random_input, opcode, response);
    if (status)
    {
        printf("puf service failed %d\n", status);
        return;
    }


    printf("\npuf response:\n");
    for (int i = 0; i < 32; i++)
    {
        printf("%2.2x", response[i]);
    }
    printf("\n");

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

    /* Demo */
    Device_Serial_Number_Print();
    Print_random_number();
    Print_random_number();
    puf_demo(1);
    
    return error;
}