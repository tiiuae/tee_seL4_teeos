#pragma once

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