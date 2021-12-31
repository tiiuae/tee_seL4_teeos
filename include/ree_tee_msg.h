/*
 * Copyright 2021, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#define RNG_SIZE_IN_BYTES 32
#define SNVM_PAGE_LENGTH  252
#define USER_KEY_LENGTH   12
#define DEVICE_ID_LENGTH  16
#define PUF_CHALLENGE     16
#define PUF_RESPONSE      32
#define NVM_PARAM_LENGTH  256

enum ree_tee_msg {
    REE_TEE_STATUS_REQ = 0,
    REE_TEE_STATUS_RESP,
    REE_TEE_RNG_REQ,
    REE_TEE_RNG_RESP,
    REE_TEE_SNVM_READ_REQ,
    REE_TEE_SNVM_READ_RESP,
    REE_TEE_SNVM_WRITE_REQ,
    REE_TEE_SNVM_WRITE_RESP,
    REE_TEE_DEVICEID_REQ,
    REE_TEE_DEVICEID_RESP,
    REE_TEE_PUF_REQ,
    REE_TEE_PUF_RESP,
    REE_TEE_NVM_PARAM_REQ,
    REE_TEE_NVM_PARAM_RESP,
    INVALID = -1,
};

enum tee_status {
    TEE_NOK = -5000,
    TEE_UNKNOWN_MSG,
    TEE_INVALID_MSG_SIZE,
    TEE_IPC_CMD_ERR,
    TEE_OK = 1,
};

struct ree_tee_hdr
{
    int32_t msg_type;
    int32_t status;
    uint32_t length;    /* total length of header + payload */
};

struct ree_tee_status_req
{
    struct ree_tee_hdr hdr;
};

struct ree_tee_status_resp
{
    struct ree_tee_hdr hdr;
};

struct ree_tee_rng_cmd
{
    struct ree_tee_hdr hdr;
    uint8_t response[RNG_SIZE_IN_BYTES];
};

struct ree_tee_nvm_param_cmd
{
    struct ree_tee_hdr hdr;
    uint8_t response[NVM_PARAM_LENGTH];
};

struct ree_tee_deviceid_cmd
{
    struct ree_tee_hdr hdr;
    uint8_t response[DEVICE_ID_LENGTH];
};

struct ree_tee_snvm_cmd
{
    struct ree_tee_hdr hdr;
    uint32_t snvm_length; /* SNVM data length, 236 for secure and 252 for plain*/
    uint8_t user_key[USER_KEY_LENGTH];
    uint8_t data[SNVM_PAGE_LENGTH];
    uint8_t page_number;
};

struct ree_tee_puf_cmd
{
    struct ree_tee_hdr hdr;
    uint8_t request[PUF_CHALLENGE];
    uint8_t response[PUF_RESPONSE];
    uint8_t opcode;
};

