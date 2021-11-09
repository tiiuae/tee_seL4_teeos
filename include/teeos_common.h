#pragma once

#include <sel4/simple_types.h>
#include <sel4utils/vspace.h>


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
    uint32_t buf_len;
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
    IPC_CMD_CH_ADDR = 0x8000,
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