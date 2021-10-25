#pragma once

#include <sel4/simple_types.h>
#include <sel4utils/vspace.h>


/****  Common definitions with REE  ****/
#define COMM_MAGIC_TEE          0x87654321
#define COMM_MAGIC_REE          0xFEDCBA98

struct tee_comm_ch {
    uint32_t ree_magic;
    uint32_t tee_magic;
    uint32_t head;
    uint32_t tail;
    uint8_t buf[0];
};
/***************************************/

#define IPC_CMD_WORDS(x) (sizeof(x)/sizeof(seL4_Word))

enum ipc_cmd {
    IPC_CMD_CH_ADDR = 0x8000,
};

struct ipc_msg_ch_addr {
    seL4_Word cmd_id;
    seL4_Word ree2tee;
    seL4_Word tee2ree;
    seL4_Word len;
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