/*
 * Copyright 2022, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdint.h>
#include <string.h>

#include <sel4runtime.h>

/* Local log level */
#define ZF_LOG_LEVEL ZF_LOG_INFO
#include <utils/util.h>
#include <utils/zf_log.h>

#include "sel4_optee_serializer.h"
#include "teeos_common.h"
#include "ree_tee_msg.h"

void sel4_dealloc_memrefs(uint32_t ptypes, TEE_Param *tee_params)
{
    if (!tee_params) {
        ZF_LOGE("tee_params empty");
    }

    for (int i = 0; i < TEE_NUM_PARAMS; i++) {
        switch (TEE_PARAM_TYPE_GET(ptypes, i)) {
        case TEE_PARAM_TYPE_MEMREF_INPUT:
        case TEE_PARAM_TYPE_MEMREF_OUTPUT:
        case TEE_PARAM_TYPE_MEMREF_INOUT:
            ZF_LOGI("free: %p [%d]", tee_params[i].memref.buffer, tee_params[i].memref.size);
            free(tee_params[i].memref.buffer);
            tee_params[i].memref.buffer = NULL;
            tee_params[i].memref.size = 0;
            break;
        default:
            break;
        }
    }
}

static int sel4_optee_deserialize_memref(struct serialized_param *ser, TEE_Param *param)
{
    param->memref.buffer = malloc(ser->val_len);
    if (!param->memref.buffer) {
        ZF_LOGE("out of memory");
        return -ENOMEM;
    }

    param->memref.size = ser->val_len;
    memcpy(param->memref.buffer, ser->value, ser->val_len);

    return 0;
}

int sel4_optee_deserialize(struct serialized_param *ser_param, uint32_t ser_len,
                           uint32_t *ptypes, TEE_Param *tee_params)
{
    int err = -1;
    struct serialized_param *param = ser_param;

    /* additional buffer overflow check */
    uintptr_t param_end = (uintptr_t)ser_param + ser_len;

    if (!ser_param || !ptypes || !tee_params) {
        ZF_LOGE("Invalid params");
        err = -EINVAL;
        goto out;
    }

    if (ser_len < (sizeof(struct serialized_param) * TEE_NUM_PARAMS)) {
        ZF_LOGE("Invalid param len: %d", ser_len);
        err = -EINVAL;
        goto out;
    }

    ZF_LOGI("param len: %d", ser_len);
    app_hexdump(ser_param, ser_len);

    memset(tee_params, 0x0, sizeof(TEE_Param) * TEE_NUM_PARAMS);

    *ptypes = TEE_PARAM_TYPE_NONE;

    for (int i = 0; i < TEE_NUM_PARAMS; i++) {
        if ((uintptr_t)param >= param_end) {
            ZF_LOGE("Buffer overflow");
            err = -ENOSPC;
            goto out;
        }

        *ptypes |= TEE_PARAM_TYPE_SET(param->param_type, i);

        switch (param->param_type) {
        case TEE_PARAM_TYPE_NONE:
            ZF_LOGI("TEE_PARAM_TYPE_NONE");
            break;
        case TEE_PARAM_TYPE_VALUE_INPUT:
        case TEE_PARAM_TYPE_VALUE_OUTPUT:
        case TEE_PARAM_TYPE_VALUE_INOUT:
            ZF_LOGF("NOT SUPPORTED");
            break;
        case TEE_PARAM_TYPE_MEMREF_INPUT:
        case TEE_PARAM_TYPE_MEMREF_OUTPUT:
        case TEE_PARAM_TYPE_MEMREF_INOUT:
            ZF_LOGI("TEE_PARAM_TYPE_MEMREF: %d", param->val_len);
            err = sel4_optee_deserialize_memref(param, &tee_params[i]);
            if (err) {
                goto out;
            }
            break;
        default:
            ZF_LOGE("Uknown param type");
            err = -EPERM;
            goto out;
        }

        /* Move pointer to the next param */
        param = (struct serialized_param *)(param->value + param->val_len);
    }

    ZF_LOGI("param types: 0%x", *ptypes);

    err = 0;

out:
    if (err) {
        sel4_dealloc_memrefs(*ptypes, tee_params);
        *ptypes = TEE_PARAM_TYPE_NONE;
    }

    return err;
}

static int sel4_optee_alloc_ser_buf(uint8_t **buf, uint32_t *buf_len,
                                    uint32_t ptypes, TEE_Param *tee_params)
{
    uint32_t len = sizeof(struct serialized_param) * TEE_NUM_PARAMS;

    for (int i = 0; i < TEE_NUM_PARAMS; i++) {
        switch (TEE_PARAM_TYPE_GET(ptypes, i)) {
        case TEE_PARAM_TYPE_NONE:
            break;
        case TEE_PARAM_TYPE_VALUE_INPUT:
        case TEE_PARAM_TYPE_VALUE_OUTPUT:
        case TEE_PARAM_TYPE_VALUE_INOUT:
            ZF_LOGF("NOT SUPPORTED");
            break;
        case TEE_PARAM_TYPE_MEMREF_INPUT:
        case TEE_PARAM_TYPE_MEMREF_OUTPUT:
        case TEE_PARAM_TYPE_MEMREF_INOUT:
            len += tee_params[i].memref.size;
            break;
        default:
            ZF_LOGE("Uknown param type");
            return -EPERM;
        }
    }

    *buf = malloc(len);
    if (!*buf) {
        ZF_LOGE("out of memory");
        return -ENOMEM;
    }

    memset(*buf, 0x0, len);

    *buf_len = len;

    ZF_LOGI("buffer len: %d", len);

    return 0;
}

int sel4_optee_serialize(struct serialized_param **ser_param, uint32_t *ser_len,
                         uint32_t ptypes, TEE_Param *tee_params)
{
    int err = -1;
    uint32_t len = 0;
    uint8_t *buf = NULL;
    struct serialized_param *param = NULL;

    err = sel4_optee_alloc_ser_buf(&buf, &len, ptypes, tee_params);
    if (err) {
        goto out;
    }

    param = (struct serialized_param *)buf;

    for (int i = 0; i < TEE_NUM_PARAMS; i++) {
        param->param_type = TEE_PARAM_TYPE_GET(ptypes, i);
        switch (param->param_type) {
        case TEE_PARAM_TYPE_NONE:
            param->val_len = 0;
            ZF_LOGI("TEE_PARAM_TYPE_NONE");
            break;
        case TEE_PARAM_TYPE_VALUE_INPUT:
        case TEE_PARAM_TYPE_VALUE_OUTPUT:
        case TEE_PARAM_TYPE_VALUE_INOUT:
            ZF_LOGF("STUB");
            break;
        case TEE_PARAM_TYPE_MEMREF_INPUT:
        case TEE_PARAM_TYPE_MEMREF_OUTPUT:
        case TEE_PARAM_TYPE_MEMREF_INOUT:
            ZF_LOGI("TEE_PARAM_TYPE_MEMREF: %d", tee_params[i].memref.size);
            param->val_len = tee_params[i].memref.size;
            memcpy(param->value, tee_params[i].memref.buffer, param->val_len);
            break;
        default:
            ZF_LOGE("Uknown param type");
            err = -EPERM;
            goto out;
        }

        /* Move to next param */
        param = (struct serialized_param *)(param->value + param->val_len);
    }

    *ser_len = len;
    *ser_param = (struct serialized_param *)buf;

    ZF_LOGI("param len: %d", len);
    app_hexdump(buf, len);

    err = 0;
out:
    if (err) {
        free(buf);
    }

    return err;
}
