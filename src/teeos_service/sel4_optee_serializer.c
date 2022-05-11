/*
 * Copyright 2022, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdint.h>
#include <string.h>

#include <sel4runtime.h>

/* Local log level */
#define ZF_LOG_LEVEL    ZF_LOG_ERROR
#include <utils/util.h>
#include <utils/zf_log.h>
#include <utils/debug.h>

#include "sel4_optee_serializer.h"
#include "teeos_common.h"
#include "ree_tee_msg.h"

#include "pkcs11_service.h"
#include <tee_fs.h>

static TEE_Param ta_param[TEE_NUM_PARAMS] = { 0 };
static TEE_Param ref_param[TEE_NUM_PARAMS] = { 0 };

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

    if (ZF_LOG_OUTPUT_DEBUG)
        utils_memory_dump(ser->value, ser->val_len, 1);

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

            if (ZF_LOG_OUTPUT_DEBUG)
                utils_memory_dump(param->value, param->val_len, 1);

            break;
        case TEE_PARAM_TYPE_MEMREF_INPUT:
        case TEE_PARAM_TYPE_MEMREF_OUTPUT:
        case TEE_PARAM_TYPE_MEMREF_INOUT:
            ZF_LOGI("TEE_PARAM_TYPE_MEMREF [0x%x]: %d / %d", param->param_type,
                tee_params[i].memref.size, ref_params[i].memref.size);

            /* If provided parameter buffer is too short TA might update
             * parameter size value to indicate required buffer size. Use
             * original buffer length from ref_param for correct copy len.
             */
            param->val_len = tee_params[i].memref.size;

            if (tee_params[i].memref.buffer) {
                memcpy(param->value,
                       tee_params[i].memref.buffer,
                       MIN(tee_params[i].memref.size, ref_params[i].memref.size));

                if (ZF_LOG_OUTPUT_DEBUG)
                    utils_memory_dump(
                        tee_params[i].memref.buffer,
                        MIN(tee_params[i].memref.size, ref_params[i].memref.size),
                        1);
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


int sel4_optee_handle_cmd(uint8_t *buf_in_out,
                          uint32_t buf_in_len,
                          uint32_t *buf_out_len,
                          uint32_t buf_max_len)
{
    int err = -1;

    struct ree_tee_optee_payload *cmd = (struct ree_tee_optee_payload*) buf_in_out;

    uint32_t param_len = buf_in_len - sizeof(struct ree_tee_optee_payload);

    uint32_t ptypes = TEE_PARAM_TYPE_NONE;

    uint32_t ta_err = 0;

    struct serialized_param *reply_param = NULL;

    if (!buf_in_out || !buf_out_len) {
        ZF_LOGE("Invalid params");
        return -EINVAL;
    }

    memset(ta_param, 0x0, sizeof(ta_param));

    err = sel4_optee_deserialize((struct serialized_param *)cmd->params,
                                 param_len,
                                 &ptypes,
                                 ta_param);
    if (err) {
        goto err_out;
    }

    /* Save buffer lengths before calling TA. TA might change the memref.size
     * without changing the actual memory allocation.
     */
    memcpy(ref_param, ta_param, sizeof(ta_param));

    switch (cmd->optee_cmd) {
    case OPTEE_OPEN_SESSION:
        ZF_LOGI("OPTEE_OPEN_SESSION");
        ta_err = sel4_init_pkcs11_session();
        break;
    case OPTEE_INVOKE:
        ZF_LOGI("OPTEE_INVOKE");
        ta_err = sel4_execute_pkcs11_command(ta_param, ptypes, cmd->ta_cmd);
        break;
    case OPTEE_CLOSE_SESSION:
        ZF_LOGI("OPTEE_CLOSE");
        ta_err = sel4_close_pkcs11_session();
        break;
    default:
        ZF_LOGE("Unknown cmd: %d",cmd->optee_cmd);
        err = -EINVAL;
        goto err_out;
    };

    cmd->ta_result = ta_err;

    if (ta_err)
        ZF_LOGE("ta_err: %d", ta_err);

    param_len = 0;
    err = sel4_optee_serialize(&reply_param, &param_len, ptypes, ta_param, ref_param);
    if (err) {
        goto err_out;
    }

    if (param_len > (buf_max_len - sizeof(struct ree_tee_optee_payload))) {
        ZF_LOGE("param buffer too long");
        err = -ENOMEM;
        goto err_out;
    }

    *buf_out_len = sizeof(struct ree_tee_optee_payload) + param_len;

    memcpy(cmd->params, reply_param, param_len);
    cmd->fs_counter = ramdisk_fs_read_storage_counter();
    sel4_dealloc_memrefs(ptypes, ta_param);
    free(reply_param);

    return 0;

err_out:

    sel4_dealloc_memrefs(ptypes, ta_param);
    free(reply_param);

    return err;
}
