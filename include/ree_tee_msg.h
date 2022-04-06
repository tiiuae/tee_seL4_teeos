/*
 * Copyright 2021, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _REE_TEE_MSG_H_
#define _REE_TEE_MSG_H_

#include <stdint.h>

#define RNG_SIZE_IN_BYTES 32
#define DEVICE_ID_LENGTH  16
#define HASH_LENGTH       48


enum ree_tee_msg {
    REE_TEE_STATUS_REQ = 0,
    REE_TEE_STATUS_RESP,
    REE_TEE_RNG_REQ,
    REE_TEE_RNG_RESP,
    REE_TEE_DEVICEID_REQ,
    REE_TEE_DEVICEID_RESP,
    REE_TEE_OPTEE_CMD_REQ,
    REE_TEE_OPTEE_CMD_RESP,
    REE_TEE_CONFIG_REQ,
    REE_TEE_CONFIG_RESP,
    REE_TEE_OPTEE_INIT_REQ,
    REE_TEE_OPTEE_INIT_RESP,
    REE_TEE_OPTEE_EXPORT_STORAGE_REQ,
    REE_TEE_OPTEE_EXPORT_STORAGE_RESP,
    REE_TEE_OPTEE_IMPORT_STORAGE_REQ,
    REE_TEE_OPTEE_IMPORT_STORAGE_RESP,

    REE_TEE_INVALID = -1,
};

enum tee_status {
    TEE_NOK = -9000,            /* RL_ERRORS_BASE: -5000 */
    TEE_UNKNOWN_MSG,
    TEE_INVALID_MSG_SIZE,
    TEE_IPC_CMD_ERR,
    TEE_OUT_OF_MEMORY,
    TEE_SYSTEM_ERR,
    TEE_PAYLOAD_OVERFLOW,
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

struct ree_tee_config_cmd
{
    struct ree_tee_hdr hdr;
    uint64_t debug_config;
};

struct ree_tee_rng_cmd
{
    struct ree_tee_hdr hdr;
    uint8_t response[RNG_SIZE_IN_BYTES];
};

struct ree_tee_deviceid_cmd
{
    struct ree_tee_hdr hdr;
    uint8_t response[DEVICE_ID_LENGTH];
};

enum optee_cmd_id {
    OPTEE_INVALID_CMD = 0,
    OPTEE_OPEN_SESSION,
    OPTEE_INVOKE,
    OPTEE_CLOSE_SESSION,
};

#define TA_CMD_NA   0xFFFFFFFF
struct ree_tee_optee_payload
{
    uint32_t optee_cmd;
    uint32_t ta_cmd;
    uint32_t ta_result;
    uint8_t params[0];
};

struct ree_tee_optee_cmd
{
    struct ree_tee_hdr hdr;
    struct ree_tee_optee_payload cmd;
};

struct ree_tee_optee_storage_bin {
    uint32_t pos;
    uint32_t storage_len;
    uint32_t payload_len;
    uint8_t payload[0];
};

struct ree_tee_optee_storage_cmd
{
    struct ree_tee_hdr hdr;
    struct ree_tee_optee_storage_bin storage;
};

#endif /* _REE_TEE_MSG_H_ */