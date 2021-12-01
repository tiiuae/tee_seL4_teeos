#pragma once

#include <sel4/types.h>

/****  Common definitions with REE  ****/
#define COMM_MAGIC_TEE          0x87654321
#define COMM_MAGIC_REE          0xFEDCBA98

struct tee_comm_ctrl {
    uint32_t ree_magic;
    uint32_t tee_magic;
    int32_t head;
    int32_t tail;
};

struct tee_comm_ch {
    struct tee_comm_ctrl *ctrl;
    int32_t buf_len;
    char *buf;
};
/***************************************/

enum comm_ch_tee {
    COMM_CH_REE2TEE = 0,
    COMM_CH_TEE2REE = 1,
    COMM_CH_COUNT,
};

#define IPC_CMD_WORDS(x) (sizeof(x)/sizeof(seL4_Word))

enum ipc_cmd {
    IPC_CMD_CH_ADDR_REQ = 0x8000,
    IPC_CMD_CH_ADDR_RESP,
    IPC_CMD_APP_EP_REQ,
    IPC_CMD_APP_EP_RESP,
};

struct ipc_msg_req {
    seL4_Word cmd_id;
};

struct ipc_msg_ch_addr {
    seL4_Word cmd_id;
    seL4_Word ctrl;             /* Buffers ctrl data area */
    seL4_Word ctrl_len;         /* Ctrl area length */
    seL4_Word ree2tee;          /* REE->TEE circular buffer */
    seL4_Word ree2tee_len;      /* Buffer length */
    seL4_Word tee2ree;          /* TEE->REE circular buffer*/
    seL4_Word tee2ree_len;      /* Buffer length */
};

struct ipc_msg_app_ep {
    seL4_Word cmd_id;
    seL4_Word app_ep;
};

#define SINGLE_WORD_MSG         1

static inline int ipc_msg_call(seL4_Word cmd,
                               seL4_CPtr ep,
                               const uint32_t resp_words,
                               seL4_Word *resp_buf)
{
    /* IPC request*/
    struct ipc_msg_req ipc_req = {
        .cmd_id = cmd,
    };

    seL4_MessageInfo_t msg_info = { 0 };
    seL4_Word msg_len = 0;

    msg_info = seL4_MessageInfo_new(0, 0, 0, SINGLE_WORD_MSG);

    seL4_SetMR(0, ipc_req.cmd_id);

    msg_info = seL4_Call(ep, msg_info);

    msg_len = seL4_MessageInfo_get_length(msg_info);
    if (msg_len != resp_words) {
        ZF_LOGF("invalid resp len: %ld / %d", msg_len, resp_words);
        return -EINVAL;
    }

    for (uint32_t i = 0; i < resp_words; i++) {
        resp_buf[i] = seL4_GetMR(i);
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