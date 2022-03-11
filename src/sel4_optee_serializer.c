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
            free(tee_params[i].memref.buffer);
            tee_params[i].memref.buffer = NULL;
            tee_params[i].memref.size = 0;
            break;
        default:
            break;
        }
    }
}

static int sel4_optee_deserialize_memref(struct serialized_param *ser, TEE_Param *params)
{
    params->memref.size = ser->val_len;

    /* zero length buffer is legal */
    if (params->memref.size == 0) {
        params->memref.buffer = NULL;
        return 0;
    }

    params->memref.buffer = malloc(params->memref.size);
    if (!params->memref.buffer) {
        ZF_LOGE("out of memory");
        return -ENOMEM;
    }

    memcpy(params->memref.buffer, ser->value, ser->val_len);

    app_hexdump(ser->value, ser->val_len);

    return 0;
}

static int sel4_optee_deserialize_value(struct serialized_param *ser, TEE_Param *params)
{
    if (ser->val_len != sizeof(params->value)) {
        ZF_LOGE("Invalid param len: %d", ser->val_len);
        return -EINVAL;
    }

    memcpy(&params->value, ser->value, ser->val_len);

    ZF_LOGI("TEE_PARAM_TYPE_VALUE [0x%x]: a: 0x%x, b: 0x%x", ser->param_type,
        params->value.a, params->value.b);

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
            err = sel4_optee_deserialize_value(param, &tee_params[i]);
            if (err) {
                goto out;
            }
            break;
        case TEE_PARAM_TYPE_MEMREF_INPUT:
        case TEE_PARAM_TYPE_MEMREF_OUTPUT:
        case TEE_PARAM_TYPE_MEMREF_INOUT:
            ZF_LOGI("TEE_PARAM_TYPE_MEMREF [0x%x]: %d", param->param_type,
                param->val_len);
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
            len += sizeof(tee_params->value);
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

    *buf = calloc(1, len);
    if (!*buf) {
        ZF_LOGE("out of memory");
        return -ENOMEM;
    }

    *buf_len = len;

    return 0;
}

int sel4_optee_serialize(struct serialized_param **ser_param, uint32_t *ser_len,
                         uint32_t ptypes, TEE_Param *tee_params, TEE_Param *ref_params)
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
            ZF_LOGI("TEE_PARAM_TYPE_VALUE [0x%x], a: 0x%x, b: 0x%x", param->param_type,
                tee_params[i].value.a, tee_params[i].value.b);

            param->val_len = sizeof(tee_params->value);
            memcpy(param->value, &tee_params[i].value, param->val_len);
            app_hexdump(param->value, param->val_len);
            break;
        case TEE_PARAM_TYPE_MEMREF_INPUT:
        case TEE_PARAM_TYPE_MEMREF_OUTPUT:
        case TEE_PARAM_TYPE_MEMREF_INOUT:
            ZF_LOGI("TEE_PARAM_TYPE_MEMREF: %d / %d", tee_params[i].memref.size,
                ref_params[i].memref.size);

            /* If provided parameter buffer is too short TA might update
             * parameter size value to indicate required buffer size. Use
             * original buffer length from ref_param for correct copy len.
             */
            param->val_len = tee_params[i].memref.size;

            if (tee_params[i].memref.buffer) {
                memcpy(param->value,
                       tee_params[i].memref.buffer,
                       MIN(tee_params[i].memref.size, ref_params[i].memref.size));

                app_hexdump(tee_params[i].memref.buffer,
                            MIN(tee_params[i].memref.size, ref_params[i].memref.size));
            }
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

    err = 0;
out:
    if (err) {
        free(buf);
    }

    return err;
}
