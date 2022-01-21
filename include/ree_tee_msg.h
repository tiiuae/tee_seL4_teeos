/*
 * Copyright 2021, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _REE_TEE_MSG_H_
#define _REE_TEE_MSG_H_

#define RNG_SIZE_IN_BYTES 32
#define SNVM_PAGE_LENGTH  252
#define USER_KEY_LENGTH   12
#define DEVICE_ID_LENGTH  16
#define PUF_CHALLENGE     16
#define PUF_RESPONSE      32
#define NVM_PARAM_LENGTH  256
#define HASH_LENGTH       48
#define SIGN_RESP_LENGTH  104
#define RAW_FORMAT        0x19
#define DER_FORMAT        0x1A

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
    REE_TEE_SIGN_REQ,
    REE_TEE_SIGN_RESP,
    REE_TEE_GEN_KEY_REQ,
    REE_TEE_GEN_KEY_RESP,
    REE_TEE_EXT_PUBKEY_REQ,
    REE_TEE_EXT_PUBKEY_RESP,
    REE_TEE_INVALID = -1,
};

enum tee_status {
    TEE_NOK = -5000,
    TEE_UNKNOWN_MSG,
    TEE_INVALID_MSG_SIZE,
    TEE_IPC_CMD_ERR,
    TEE_OUT_OF_MEMORY,
    TEE_OK = 1,
};

enum key_format {
    KEY_UNKNOWN = -10,
    KEY_RSA = 1,
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

struct ree_tee_sign_cmd
{
    struct ree_tee_hdr hdr;
    uint8_t hash[HASH_LENGTH];
    uint8_t response[SIGN_RESP_LENGTH];
    uint8_t format;
};

struct ree_tee_key_info
{
    char name[24];
    uint8_t guid[32];
    uint32_t client_id;
    uint32_t key_nbits;
    uint32_t format;
    uint64_t counter;
    uint32_t pubkey_length;
    uint32_t privkey_length;
};


struct ree_tee_key_data_storage
{
    uint32_t storage_size;
    struct ree_tee_key_info key_info;
    uint8_t keys[0];
};

struct ree_tee_key_req_cmd
{
    struct ree_tee_hdr hdr;
    struct ree_tee_key_info key_req_info;
};

struct ree_tee_key_resp_cmd
{
    struct ree_tee_hdr hdr;
    struct ree_tee_key_info key_data_info;
    struct ree_tee_key_data_storage key_data;
};

struct ree_tee_pub_key_req_cmd
{
    struct ree_tee_hdr hdr;
    uint32_t client_id;
    uint8_t guid[32];
    uint8_t crypted_key_data[0];
};

struct ree_tee_pub_key_resp_cmd
{
    struct ree_tee_hdr hdr;
    struct ree_tee_key_info key_info;
    uint8_t pubkey[0];
};

#endif /* _REE_TEE_MSG_H_ */