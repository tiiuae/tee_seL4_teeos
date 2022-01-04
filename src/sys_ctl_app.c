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

void *app_shared_memory;

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
    app_shared_memory = (void*)ipc_resp.shared_memory;

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

static void handle_service_requests(void)
{
    seL4_MessageInfo_t msg_info = {0};
    seL4_Word msg_len = 0;
    seL4_Word sender_badge = 0;
    seL4_Word msg_data = 0;

    while(1)
    {
        ZF_LOGI("Wait msg from comm app...");
        msg_info = seL4_Recv(ipc_app_ep1, &sender_badge);
        msg_len = seL4_MessageInfo_get_length(msg_info);

        if (msg_len > 0) {
            msg_data = seL4_GetMR(0);
        }

        ZF_LOGI("msg from 0x%lx (%ld) 0x%lx", sender_badge, msg_len, msg_data);

        switch (msg_data)
        {
            case IPC_CMD_SYS_CTL_RNG_REQ:
            {
                ZF_LOGI("RNG request");
                memset(app_shared_memory,0,32);
                int err = nonce_service(app_shared_memory);
                if (!err) {
                    seL4_SetMR(0, IPC_CMD_SYS_CTL_RNG_RESP);
                }
                else {
                    ZF_LOGI("RNG service failed");
                    seL4_SetMR(0, IPC_CMD_SYS_FAIL);
                }
                seL4_Reply(msg_info);
            }
            break;
            case IPC_CMD_SYS_CTL_NVM_PARAM_REQ:
            {
                ZF_LOGI("NVM parameter request");
                memset(app_shared_memory,0, 256);
                int err = read_nvm_parameters(app_shared_memory);
                if (!err) {
                    seL4_SetMR(0, IPC_CMD_SYS_CTL_NVM_PARAM_RESP);
                }
                else {
                    ZF_LOGI("Nvm param request failed");
                    seL4_SetMR(0, IPC_CMD_SYS_FAIL);
                }
                seL4_Reply(msg_info);
            }
            break;
            case IPC_CMD_SYS_CTL_SNVM_WRITE_REQ:
            {
                uint8_t page = (uint8_t)seL4_GetMR(1);
                uint8_t *usk = (uint8_t*)seL4_GetMR(2);
                uint8_t *data = (uint8_t*)seL4_GetMR(3);
                uint16_t length = (uint16_t)seL4_GetMR(4);
                uint8_t mode = MSS_SYS_SNVM_NON_AUTHEN_TEXT_REQUEST_CMD;

                if (length == 236) {
                    mode = MSS_SYS_SNVM_AUTHEN_CIPHERTEXT_REQUEST_CMD;
                    ZF_LOGI("sNVM Secure write");
                }

                int err = secure_nvm_write(mode, page, data, usk);

                if (!err) {
                    seL4_SetMR(0, IPC_CMD_SYS_CTL_SNVM_WRITE_RESP);
                }
                else {
                    ZF_LOGI("sNVM write service to page %d failed: %d",page, err);
                    seL4_SetMR(0, IPC_CMD_SYS_FAIL);
                }
                seL4_Reply(msg_info);
            }
            break;
            case IPC_CMD_SYS_CTL_SNVM_READ_REQ:
            {
                uint32_t *adminw;
                uint8_t admin[4];
                uint8_t page = (uint8_t)seL4_GetMR(1);
                uint8_t *usk = (uint8_t*)seL4_GetMR(2);
                uint8_t *data = (uint8_t*)seL4_GetMR(3);
                uint16_t length = (uint16_t)seL4_GetMR(4);

                if (length == 236) {
                    ZF_LOGI("sNVM Secure Read");
                }

                int err = secure_nvm_read(page,usk, admin ,data, length);
                adminw = (void *)admin;
                if (!err) {
                    seL4_SetMR(0, IPC_CMD_SYS_CTL_SNVM_READ_RESP);
                    ZF_LOGI("Admin was 0x%x", *adminw);
                }
                else {
                    ZF_LOGI("sNVM Read  service from page %d failed: %d",page, err);
                    seL4_SetMR(0, IPC_CMD_SYS_FAIL);
                }
                seL4_Reply(msg_info);
            }
            break;
            case IPC_CMD_SYS_CTL_DEVICEID_REQ:
            {
                ZF_LOGI("device id request");
                memset(app_shared_memory, 0, MSS_SYS_SERIAL_NUMBER_RESP_LEN);

                int err = get_serial_number(app_shared_memory);
                msg_info = seL4_MessageInfo_new(0, 0, 0, 1);
                if (!err) {
                    seL4_SetMR(0, IPC_CMD_SYS_CTL_DEVICEID_RESP);
                }
                else {
                    ZF_LOGI("device id service failed");
                    seL4_SetMR(0, IPC_CMD_SYS_FAIL);
                }
                seL4_Reply(msg_info);
            }
            break;
            case IPC_CMD_SYS_CTL_PUF_REQ:
            {
                ZF_LOGI("Puf request");
                uint8_t *challenge = (uint8_t*)seL4_GetMR(1);
                uint8_t opcode = (uint8_t)seL4_GetMR(2);
                uint8_t *response = (uint8_t*)seL4_GetMR(3);
                ZF_LOGI("Puf request C=%p O=%d, R=%p", challenge, opcode, response );

                int err = puf_emulation_service(challenge, opcode, response);

                msg_info = seL4_MessageInfo_new(0, 0, 0, 1);
                if (!err) {
                    seL4_SetMR(0, IPC_CMD_SYS_CTL_PUF_RESP);
                }
                else {
                    ZF_LOGI("puf service failed");
                    seL4_SetMR(0, IPC_CMD_SYS_FAIL);
                }
                seL4_Reply(msg_info);
            }
            break;
            case IPC_CMD_SYS_CTL_SIGN_REQ:
            {
                ZF_LOGI("Sign request");
                uint8_t *hash = (uint8_t*)seL4_GetMR(1);
                uint8_t format = (uint8_t)seL4_GetMR(2);
                uint8_t *response = (uint8_t*)seL4_GetMR(3);
                ZF_LOGI("Sign request hash=%p format=%d, R=%p", hash, format, response );

                int err = digital_signature_service(hash, format, response);

                msg_info = seL4_MessageInfo_new(0, 0, 0, 1);
                if (!err) {
                    seL4_SetMR(0, IPC_CMD_SYS_CTL_SIGN_RESP);
                }
                else {
                    ZF_LOGI("puf service failed");
                    seL4_SetMR(0, IPC_CMD_SYS_FAIL);
                }
                seL4_Reply(msg_info);
            }
            break;
            default:
                ZF_LOGI("Unsupported message %lu", msg_data);
                seL4_SetMR(0, 0);
                seL4_Reply(msg_info);
                break;
        }
    }
}



/*
 * Demo functions to demonstrate system controller services
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
    printf("Inuput 16-byte random:\n");
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

    handle_service_requests();
    return error;
}