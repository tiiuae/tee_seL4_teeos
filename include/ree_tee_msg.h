/*
 * Copyright 2021, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#define RNG_SIZE_IN_BYTES 32

enum ree_tee_msg {
    REE_TEE_STATUS_REQ = 0,
    REE_TEE_STATUS_RESP,
    REE_TEE_RNG_REQ,
    REE_TEE_RNG_RESP,
    INVALID = -1,
};

enum tee_status {
    TEE_OK = 1,
    TEE_NOK = -1,
};



struct ree_tee_status_req
{
    int32_t msg_type;
    uint32_t length;
};

struct ree_tee_status_resp
{
    int32_t msg_type;
    uint32_t length;
    uint32_t status;
};

struct ree_tee_rng_req
{
    int32_t msg_type;
    uint32_t length;
};

struct ree_tee_rng_resp
{
    int32_t msg_type;
    uint32_t length;
    uint8_t response[RNG_SIZE_IN_BYTES];
};