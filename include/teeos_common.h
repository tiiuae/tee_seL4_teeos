/*
 * Copyright 2022, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#pragma once

#include <sel4/types.h>
#include <errno.h>

#define IPC_CMD_WORDS(x) (sizeof(x)/sizeof(seL4_Word))

enum ipc_cmd {
    IPC_CMD_CH_ADDR_REQ = 0x8000,
    IPC_CMD_CH_ADDR_RESP,
    IPC_CMD_CRASHLOG_REQ,
    IPC_CMD_CRASHLOG_RESP,
    IPC_CMD_APP_EP_REQ,
    IPC_CMD_APP_EP_RESP,
    IPC_CMD_RPMSG_CONF_REQ,
    IPC_CMD_RPMSG_CONF_RESP,
    IPC_CMD_SYS_CTL_ADDR_REQ,
    IPC_CMD_SYS_CTL_ADDR_RESP,
    IPC_CMD_SYS_CTL_RNG_REQ,
    IPC_CMD_SYS_CTL_RNG_RESP,
    IPC_CMD_SYS_CTL_SNVM_READ_REQ,
    IPC_CMD_SYS_CTL_SNVM_READ_RESP,
    IPC_CMD_SYS_CTL_SNVM_WRITE_REQ,
    IPC_CMD_SYS_CTL_SNVM_WRITE_RESP,
    IPC_CMD_SYS_CTL_DEVICEID_REQ,
    IPC_CMD_SYS_CTL_DEVICEID_RESP,
    IPC_CMD_SYS_CTL_PUF_REQ,
    IPC_CMD_SYS_CTL_PUF_RESP,
    IPC_CMD_SYS_CTL_NVM_PARAM_REQ,
    IPC_CMD_SYS_CTL_NVM_PARAM_RESP,
    IPC_CMD_SYS_CTL_SIGN_REQ,
    IPC_CMD_SYS_CTL_SIGN_RESP,
    IPC_CMD_KEY_CREATE_REQ,
    IPC_CMD_KEY_CREATE_RESP,
    IPC_CMD_KEY_PUBEXT_REQ,
    IPC_CMD_KEY_PUBEXT_RESP,
    IPC_CMD_KEY_IMPORT_REQ,
    IPC_CMD_KEY_IMPORT_RESP,
    IPC_CMD_SYS_FAIL = 0x8FFF,
    IPC_CMD_UNKNOWN,
    IPC_CMD_EMPTY,
};

struct ipc_msg_req {
    seL4_Word cmd_id;
};

struct ipc_msg_ch_addr {
    seL4_Word cmd_id;
    seL4_Word shared_memory;    /* Shared memory for applications */
    seL4_Word shared_len;       /* Shared memory length */

};

struct ipc_msg_crash_log_addr {
    seL4_Word cmd_id;
    seL4_Word crashlog;         /* Crashlog shared memory */
};

struct ipc_msg_ihc_buf {
    seL4_Word cmd_id;
    seL4_Word ihc_buf_va;       /* IHC buffer, app addr */
    seL4_Word ihc_buf_pa;       /* IHC buffer, physical addr */
    seL4_Word ihc_irq;          /* IHC irq */
    seL4_Word ihc_ntf;          /* IHC irq notfication */
    seL4_Word vring_va;         /* vring comm_app addr */
    seL4_Word vring_pa;         /* vring physical addr */
};

struct ipc_msg_cys_ctl_addr {
    seL4_Word cmd_id;
    seL4_Word reg_base;          /* System controller register base address */
    seL4_Word mbox_base;         /* mailbox base address */
    seL4_Word mbox_len;          /* mailbox length (2k) */
    seL4_Word msg_int_reg;       /* message interrupt register */
    seL4_Word shared_memory;     /* Shared memory for applications */
    seL4_Word shared_len;        /* Shared memory length */
};

struct ipc_msg_app_ep {
    seL4_Word cmd_id;
    seL4_Word app_ep;
};

struct ipc_msg_key_create_resp {
    seL4_Word cmd_id;
    seL4_Word keyblob_offset;
};

struct ipc_msg_pubkey_export_req {
    seL4_Word cmd_id;
    seL4_Word key_blob_size;
};

struct ipc_msg_pubkey_export_resp {
    seL4_Word cmd_id;
    seL4_Word key_info_offset;
    seL4_Word pubkey_offset;
};

struct ipc_msg_key_import_req {
    seL4_Word cmd_id;
    seL4_Word key_blob_size;
};

#define SINGLE_WORD_MSG         1

static inline int ipc_msg_call(seL4_CPtr ep,
                               const uint32_t send_words,
                               seL4_Word *send_buf,
                               const seL4_Word resp_cmd,
                               const uint32_t resp_words,
                               seL4_Word *resp_buf)
{
    seL4_MessageInfo_t msg_info = { 0 };
    seL4_Word msg_len = 0;

    if (!send_buf || !resp_buf) {
        return -EINVAL;
    }

    msg_info = seL4_MessageInfo_new(0, 0, 0, send_words);

    for (uint32_t i = 0; i < send_words; i++) {
        seL4_SetMR(i, send_buf[i]);
    }

    msg_info = seL4_Call(ep, msg_info);

    msg_len = seL4_MessageInfo_get_length(msg_info);
    if (msg_len != resp_words) {
        return -EIO;
    }

    for (uint32_t i = 0; i < resp_words; i++) {
        resp_buf[i] = seL4_GetMR(i);
    }

    if (resp_buf[0] != resp_cmd) {
        return -EFAULT;
    }

    return 0;
}

static inline void app_hexdump(void* mem, size_t len)
{
    uint8_t *ch = (uint8_t*)mem;

    for (size_t i = 0; i < len; i++)
    {
        if (i % 16 == 0) {
            if (i != 0) {
                printf("\n");
            }
            printf("%p: 0x%02x", ch, *ch);
        } 
        else {
            printf(" 0x%02x", *ch);
        }

        ch++;
    }
    printf("\n");
}


