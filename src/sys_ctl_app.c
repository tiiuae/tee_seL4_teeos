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
#include <ree_tee_msg.h>
#include <key_service.h>
#include <pkcs11_service.h>
#include <utils/fence.h>
#include <utils/zf_log.h>

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
            case IPC_CMD_SYS_CTL_NVM_PARAM_REQ:
            {
                ZF_LOGI("NVM parameter request");
                memset(app_shared_memory,0, 256);
                int err = read_nvm_parameters(app_shared_memory);
                if (!err) {
                    SET_IPC_CMD_TYPE(&sel4_ipc_reply, IPC_CMD_SYS_CTL_NVM_PARAM_RESP);
                }
                else {
                    ZF_LOGI("Nvm param request failed");
                    SET_IPC_SYS_FAIL(&sel4_ipc_reply);
                }
            }
            break;
            case IPC_CMD_SYS_CTL_SNVM_WRITE_REQ:
            {
                struct ree_tee_snvm_cmd *cmd = (struct ree_tee_snvm_cmd*)app_shared_memory;

                uint8_t page = cmd->page_number;
                uint8_t *usk = cmd->user_key;
                uint8_t *data = cmd->data;
                uint16_t length = cmd->snvm_length;

                uint8_t mode = MSS_SYS_SNVM_NON_AUTHEN_TEXT_REQUEST_CMD;

                if (length == 236) {
                    mode = MSS_SYS_SNVM_AUTHEN_CIPHERTEXT_REQUEST_CMD;
                    ZF_LOGI("sNVM Secure write");
                }

                int err = secure_nvm_write(mode, page, data, usk);

                if (!err) {
                    SET_IPC_CMD_TYPE(&sel4_ipc_reply, IPC_CMD_SYS_CTL_SNVM_WRITE_RESP);

                }
                else {
                    ZF_LOGI("sNVM write service to page %d failed: %d",page, err);
                    SET_IPC_SYS_FAIL(&sel4_ipc_reply);
                }
            }
            break;
            case IPC_CMD_SYS_CTL_SNVM_READ_REQ:
            {
                uint32_t *adminw;
                uint8_t admin[4];

                struct ree_tee_snvm_cmd *cmd = (struct ree_tee_snvm_cmd *)app_shared_memory;

                uint8_t page = cmd->page_number;
                uint8_t *usk = cmd->user_key;
                uint8_t *data = cmd->data;
                uint16_t length = cmd->snvm_length;

                if (length == 236) {
                    ZF_LOGI("sNVM Secure Read");
                }

                int err = secure_nvm_read(page,usk, admin ,data, length);
                adminw = (void *)admin;
                if (!err) {
                    SET_IPC_CMD_TYPE(&sel4_ipc_reply, IPC_CMD_SYS_CTL_SNVM_READ_RESP);
                    ZF_LOGI("Admin was 0x%x", *adminw);
                }
                else {
                    ZF_LOGI("sNVM Read  service from page %d failed: %d",page, err);
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
            case IPC_CMD_SYS_CTL_PUF_REQ:
            {
                ZF_LOGI("Puf request");

                struct ree_tee_puf_cmd *cmd = (struct ree_tee_puf_cmd *)app_shared_memory;

                uint8_t *challenge = cmd->request;
                uint8_t opcode = cmd->opcode;
                uint8_t *response = cmd->response;

                ZF_LOGI("Puf request C=%p O=%d, R=%p", challenge, opcode, response );

                int err = puf_emulation_service(challenge, opcode, response);

                if (!err) {
                    SET_IPC_CMD_TYPE(&sel4_ipc_reply, IPC_CMD_SYS_CTL_PUF_RESP);
                }
                else {
                    ZF_LOGI("puf service failed");
                    SET_IPC_SYS_FAIL(&sel4_ipc_reply);
                }
            }
            break;
            case IPC_CMD_SYS_CTL_SIGN_REQ:
            {
                ZF_LOGI("Sign request");

                struct ree_tee_sign_cmd *cmd = (struct ree_tee_sign_cmd *)app_shared_memory;

                uint8_t *hash = cmd->hash;
                uint8_t format = cmd->format;
                uint8_t *response = cmd->response;

                ZF_LOGI("Sign request hash=%p format=%d, R=%p", hash, format, response );

                int err = digital_signature_service(hash, format, response);

                if (!err) {
                    SET_IPC_CMD_TYPE(&sel4_ipc_reply, IPC_CMD_SYS_CTL_SIGN_RESP);
                }
                else {
                    ZF_LOGI("puf service failed");
                    SET_IPC_SYS_FAIL(&sel4_ipc_reply);
                }
            }
            break;
            case IPC_CMD_KEY_CREATE_REQ:
            {
                ZF_LOGI("Key blob generation request");

                struct ipc_msg_key_create_resp *sel4_resp =
                    (struct ipc_msg_key_create_resp *)sel4_ipc_reply.buf;

                struct ree_tee_key_info *keyinfo_ptr =
                    (struct ree_tee_key_info*)app_shared_memory;

                struct ree_tee_key_data_storage *key_blob =
                    app_shared_memory + sizeof(struct ree_tee_key_info);

                uintptr_t key_blob_off = (uintptr_t)key_blob - (uintptr_t)app_shared_memory;

                int max_key_blob_size = shared_memory_size - sizeof(struct ree_tee_key_info);

                int err = generate_key_pair(keyinfo_ptr, key_blob, max_key_blob_size);

                if (!err) {
                    sel4_ipc_reply.len = IPC_CMD_WORDS(struct ipc_msg_key_create_resp);

                    sel4_resp->cmd_id = IPC_CMD_KEY_CREATE_RESP;
                    sel4_resp->keyblob_offset = key_blob_off;
                }
                else {
                    ZF_LOGI("Key create failed %d ", err);
                    SET_IPC_SYS_FAIL(&sel4_ipc_reply);
                }
            }
            break;
            case IPC_CMD_KEY_PUBEXT_REQ:
            {
                ZF_LOGI("Public key extraction request");

                struct ipc_msg_gen_payload *sel4_req =
                    (struct ipc_msg_gen_payload *)sel4_ipc_recv.buf;

                struct ipc_msg_pubkey_export_resp *sel4_resp =
                    (struct ipc_msg_pubkey_export_resp *)sel4_ipc_reply.buf;


                struct key_data_blob *key_data_ptr = (struct key_data_blob *)app_shared_memory;
                uint32_t key_data_length = sel4_req->payload_size;

                struct ree_tee_key_info *keyinfo_ptr = (struct ree_tee_key_info *)((uint8_t*)key_data_ptr + key_data_length);
                uintptr_t keyinfo_off = (uintptr_t)keyinfo_ptr - (uintptr_t)app_shared_memory;

                uint8_t *pubkey_ptr = (uint8_t*)keyinfo_ptr + sizeof(struct ree_tee_key_info);
                uintptr_t pubkey_off = (uintptr_t)pubkey_ptr - (uintptr_t)app_shared_memory;

                uint32_t max_size = shared_memory_size - (pubkey_ptr - (uint8_t*)app_shared_memory);
                ZF_LOGI("Max size %u clientid %u", max_size,key_data_ptr->key_data_info.client_id);

                int err = extract_public_key(key_data_ptr, key_data_length, keyinfo_ptr, pubkey_ptr, max_size);

                if (!err) {
                    sel4_ipc_reply.len = IPC_CMD_WORDS(struct ipc_msg_pubkey_export_resp);

                    sel4_resp->cmd_id = IPC_CMD_KEY_PUBEXT_RESP;
                    sel4_resp->key_info_offset = keyinfo_off;
                    sel4_resp->pubkey_offset = pubkey_off;
                }
                else {
                    ZF_LOGI("Key extraction failed %d ", err);
                    SET_IPC_SYS_FAIL(&sel4_ipc_reply);
                }
            }
            break;
            case IPC_CMD_KEY_IMPORT_REQ:
            {
                ZF_LOGI("Key import request");

                struct key_data_blob *key_data_ptr = (struct key_data_blob *)app_shared_memory;

                int err = import_key_blob(key_data_ptr);

                if (!err) {
                     SET_IPC_CMD_TYPE(&sel4_ipc_reply, IPC_CMD_KEY_IMPORT_RESP);
                }
                else {
                    ZF_LOGI("Key import failed %d ", err);
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

                ZF_LOGI("sel4_req->payload_size: %ld", sel4_req->payload_size);

                int err = sel4_optee_handle_cmd(app_shared_memory,
                                                sel4_req->payload_size,
                                                &resp_len,
                                                shared_memory_size);

                if (err) {
                    ZF_LOGI("OPTEE cmd failed %d ", err);
                    SET_IPC_SYS_FAIL(&sel4_ipc_reply);
                    break;
                }

                sel4_resp->cmd_id = IPC_CMD_OPTEE_RESP;
                sel4_resp->payload_size = resp_len;

                sel4_ipc_reply.len = IPC_CMD_WORDS(struct ipc_msg_gen_payload);
            }
            break;
            default:
                ZF_LOGI("Unsupported message 0x%lx", sel4_ipc_recv.buf[0]);
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

    error = teeos_init_optee_storage();
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
    //test_pkcs11();
    handle_service_requests();
    return error;
}