/*
 * Copyright 2021, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sel4_teeos/gen_config.h>

#include <regex.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <stdint.h>

#include <sel4runtime.h>
#include "utils/attribute.h"
#include <teeos_common.h>
#include <ree_tee_msg.h>
#include <teeos_service.h>

/* Local log level */
#define ZF_LOG_LEVEL    ZF_LOG_ERROR
#include <utils/util.h>
#include <utils/zf_log.h>

#include <sel4utils/process.h>

#include "rpmsg_sel4.h"

#include "sel4_crashlog.h"
#include "sel4_optee_serializer.h"
#include "pkcs11_ta.h"
#include "sel4_ihc.h"

static seL4_CPtr ipc_root_ep = 0;
static seL4_CPtr ipc_app_ep1 = 0;
static void *app_shared_memory;
static uint32_t app_shared_len = 0;
static struct crashlog_ctx crashlog = { 0 };

struct comm_ch {
    struct sel4_rpmsg_config rpmsg_conf;
};

static struct comm_ch comm = {0};


#define SET_REE_HDR(hdr, msg, stat, len) {  \
            (hdr)->msg_type = msg;          \
            (hdr)->status = stat;           \
            (hdr)->length = len;            \
        }

#define REE_HDR_LEN     sizeof(struct ree_tee_hdr)


/* For succesfull operation function allocates memory for reply_msg.
 * Otherwise function sets err_msg and frees all allocated memory
  */
typedef int (*ree_tee_msg_fn)(struct ree_tee_hdr*, struct ree_tee_hdr**, struct ree_tee_hdr*);

#define DECL_MSG_FN(fn_name)                           \
    static int fn_name(struct ree_tee_hdr *ree_msg,    \
                       struct ree_tee_hdr **reply_msg, \
                       struct ree_tee_hdr *reply_err)

DECL_MSG_FN(ree_tee_status_req);
DECL_MSG_FN(ree_tee_config_req);
DECL_MSG_FN(ree_tee_rng_req);
DECL_MSG_FN(ree_tee_deviceid_req);
DECL_MSG_FN(ree_tee_optee_cmd_req);
DECL_MSG_FN(ree_tee_optee_init_req);
DECL_MSG_FN(ree_tee_optee_export_storage_req);
DECL_MSG_FN(ree_tee_optee_import_storage_req);

#define FN_LIST_LEN(fn_list)    (sizeof(fn_list) / (sizeof(fn_list[0][0]) * 2))

static uintptr_t ree_tee_fn[][2] = {
    {REE_TEE_STATUS_REQ, (uintptr_t)ree_tee_status_req},
    {REE_TEE_CONFIG_REQ, (uintptr_t)ree_tee_config_req},
    {REE_TEE_RNG_REQ, (uintptr_t)ree_tee_rng_req},
    {REE_TEE_DEVICEID_REQ, (uintptr_t)ree_tee_deviceid_req},
    {REE_TEE_OPTEE_CMD_REQ, (uintptr_t)ree_tee_optee_cmd_req},
    {REE_TEE_OPTEE_INIT_REQ, (uintptr_t)ree_tee_optee_init_req},
    {REE_TEE_OPTEE_EXPORT_STORAGE_REQ, (uintptr_t)ree_tee_optee_export_storage_req},
    {REE_TEE_OPTEE_IMPORT_STORAGE_REQ, (uintptr_t)ree_tee_optee_import_storage_req},
};

static int setup_comm_ch(void)
{
    int error = -1;

    seL4_Word ipc_req = IPC_CMD_CH_ADDR_REQ;
    /* IPC response */
    struct ipc_msg_ch_addr ipc_resp = { 0 };

    ZF_LOGI("seL4_Call: IPC_CMD_CH_ADDR_REQ");

    error = ipc_msg_call(ipc_root_ep,
                         SINGLE_WORD_MSG,
                         &ipc_req,
                         IPC_CMD_CH_ADDR_RESP,
                         IPC_CMD_WORDS(ipc_resp),
                         (seL4_Word *)&ipc_resp);

    if (error) {
        ZF_LOGF("error ipc_msg_call: %d", error);
        return error;
    }

    app_shared_memory = (void *)ipc_resp.shared_memory;
    app_shared_len = ipc_resp.shared_len;

    return 0;
}

static int setup_crashlog(void)
{
    int error = -1;

    seL4_Word ipc_req = IPC_CMD_CRASHLOG_REQ;

    struct ipc_msg_crash_log_addr ipc_resp = { 0 };

    ZF_LOGI("seL4_Call: IPC_CMD_CRASHLOG_REQ");

    error = ipc_msg_call(ipc_root_ep,
                         SINGLE_WORD_MSG,
                         &ipc_req,
                         IPC_CMD_CRASHLOG_RESP,
                         IPC_CMD_WORDS(ipc_resp),
                         (seL4_Word *)&ipc_resp);

    if (error) {
        ZF_LOGF("error ipc_msg_call: %d", error);
        return error;
    }

    sel4_crashlog_setup_cb(&crashlog, (void *)ipc_resp.crashlog);

    ZF_LOGI("crashlog setup");

    return 0;
}

static int setup_ihc_buf(struct sel4_rpmsg_config *rpmsg_conf)
{
    int error = -1;

    seL4_Word ipc_req = IPC_CMD_RPMSG_CONF_REQ;
    /* IPC response */
    struct ipc_msg_ihc_buf ipc_resp = { 0 };

    ZF_LOGI("seL4_Call: IPC_CMD_RPMSG_CONF_REQ");

    error = ipc_msg_call(ipc_root_ep,
                         SINGLE_WORD_MSG,
                         &ipc_req,
                         IPC_CMD_RPMSG_CONF_RESP,
                         IPC_CMD_WORDS(ipc_resp),
                         (seL4_Word *)&ipc_resp);

    if (error) {
        ZF_LOGF("ERROR ipc_msg_call: %d", error);
        return error;
    }

    rpmsg_conf->ihc_irq = ipc_resp.ihc_irq;
    rpmsg_conf->ihc_ntf = ipc_resp.ihc_ntf;
    rpmsg_conf->vring_va = (void*)ipc_resp.vring_va;
    rpmsg_conf->vring_pa = ipc_resp.vring_pa;
    rpmsg_conf->ihc_reg_base = (void*)ipc_resp.ihc_reg;

    rpmsg_conf->irq_handler_ack = seL4_IRQHandler_Ack;
    rpmsg_conf->irq_notify_wait = seL4_Wait;

    error = sel4_ihc_init(comm.rpmsg_conf.ihc_reg_base);
    if (error) {
        return error;
    }

    ZF_LOGI("ihc_irq    [0x%lx]", rpmsg_conf->ihc_irq);
    ZF_LOGI("ihc_ntf    [0x%lx]", rpmsg_conf->ihc_ntf);
    ZF_LOGI("ihc_reg    [%p]", rpmsg_conf->ihc_reg_base);
    ZF_LOGI("vring_va   [%p]", rpmsg_conf->vring_va);
    ZF_LOGI("vring_pa   [0x%lx]", rpmsg_conf->vring_pa);

    return 0;
}

static int setup_app_ep(void)
{
    int error = -1;

    seL4_Word ipc_req = IPC_CMD_APP_EP_REQ;
    /* IPC response */
    struct ipc_msg_app_ep ipc_resp = { 0 };

    ZF_LOGI("seL4_Call: IPC_CMD_APP_EP_REQ");

    error = ipc_msg_call(ipc_root_ep,
                         SINGLE_WORD_MSG,
                         &ipc_req,
                         IPC_CMD_APP_EP_RESP,
                         IPC_CMD_WORDS(ipc_resp),
                         (seL4_Word *)&ipc_resp);

    if (error) {
        ZF_LOGF("error ipc_msg_call: %d", error);
        return error;
    }

    ipc_app_ep1 = ipc_resp.app_ep;

    ZF_LOGI("ipc_app_ep1: 0x%lx", ipc_app_ep1);

    return 0;
}

/* ree_tee_msg_fn:
 *     For succesfull operation function allocates memory for reply_msg.
 *     Otherwise function sets err_msg and frees all allocated memory
 */
static int ree_tee_status_req(struct ree_tee_hdr *ree_msg __attribute__((unused)),
                           struct ree_tee_hdr **reply_msg,
                           struct ree_tee_hdr *reply_err)
{
    int32_t reply_type = REE_TEE_STATUS_RESP;

    ZF_LOGI("%s", __FUNCTION__);

    *reply_msg = malloc(sizeof(struct ree_tee_hdr));
    if (!*reply_msg) {
        SET_REE_HDR(reply_err, reply_type, TEE_OUT_OF_MEMORY, REE_HDR_LEN);
        return TEE_OUT_OF_MEMORY;
    }

    SET_REE_HDR(*reply_msg, reply_type, TEE_OK, sizeof(struct ree_tee_hdr));

    return 0;
}
/* ree_tee_msg_fn:
 *     For succesfull operation function allocates memory for reply_msg.
 *     Otherwise function sets err_msg and frees all allocated memory
 */
static int ree_tee_config_req(struct ree_tee_hdr *ree_msg,
                           struct ree_tee_hdr **reply_msg,
                           struct ree_tee_hdr *reply_err)
{
    int err = -1;
    int32_t reply_type = REE_TEE_CONFIG_RESP;
    size_t cmd_len = sizeof(struct ree_tee_config_cmd);

    seL4_Word sel4_req = IPC_CMD_CONFIG_REQ;
    seL4_Word sel4_resp = 0;

    struct ree_tee_config_cmd *ipc = (struct ree_tee_config_cmd *)app_shared_memory;
    struct ree_tee_config_cmd *req = (struct ree_tee_config_cmd *)ree_msg;
    struct ree_tee_config_cmd *resp = NULL;

    ZF_LOGI("%s", __FUNCTION__);

    *reply_msg = malloc(cmd_len);
    if (!*reply_msg) {
        err = TEE_OUT_OF_MEMORY;
        goto err_out;
    }

    resp = (struct ree_tee_config_cmd *)*reply_msg;

    memcpy(ipc, req, cmd_len);

    /* copy data to ipc shared memory before IPC */
    THREAD_MEMORY_RELEASE();

    /*call to sys app*/
    ZF_LOGI("Send msg to sys app...");

    err = ipc_msg_call(ipc_app_ep1,
                       SINGLE_WORD_MSG,
                       &sel4_req,
                       IPC_CMD_CONFIG_RESP,
                       SINGLE_WORD_MSG,
                       &sel4_resp);

    if (err) {
        ZF_LOGE("ERROR ipc_msg_call: %d", err);
        err = TEE_IPC_CMD_ERR;
        goto err_out;
    }

    SET_REE_HDR(&resp->hdr, reply_type, TEE_OK, cmd_len);

    resp->debug_config = ipc->debug_config;

    return 0;

err_out:
    free(*reply_msg);
    *reply_msg = NULL;

    SET_REE_HDR(reply_err, reply_type, err, REE_HDR_LEN);

    return err;
}
/* ree_tee_msg_fn:
 *     For succesfull operation function allocates memory for reply_msg.
 *     Otherwise function sets err_msg and frees all allocated memory
 */
static int ree_tee_rng_req(struct ree_tee_hdr *ree_msg __attribute__((unused)),
                           struct ree_tee_hdr **reply_msg,
                           struct ree_tee_hdr *reply_err)
{
    int err = -1;
    int32_t reply_type = REE_TEE_RNG_RESP;
    size_t cmd_len = sizeof(struct ree_tee_rng_cmd);

    seL4_Word sel4_req = IPC_CMD_SYS_CTL_RNG_REQ;
    seL4_Word sel4_resp = 0;

    struct ree_tee_rng_cmd *ipc = (struct ree_tee_rng_cmd *)app_shared_memory;
    struct ree_tee_rng_cmd *resp = NULL;

    ZF_LOGI("%s", __FUNCTION__);

    *reply_msg = malloc(cmd_len);
    if (!*reply_msg) {
        err = TEE_OUT_OF_MEMORY;
        goto err_out;
    }

    resp = (struct ree_tee_rng_cmd *)*reply_msg;

    /* header only, no params for req */

    /*call to sys app*/
    ZF_LOGI("Send msg to sys app...");

    err = ipc_msg_call(ipc_app_ep1,
                       SINGLE_WORD_MSG,
                       &sel4_req,
                       IPC_CMD_SYS_CTL_RNG_RESP,
                       SINGLE_WORD_MSG,
                       &sel4_resp);

    if (err) {
        ZF_LOGE("ERROR ipc_msg_call: %d", err);
        err = TEE_IPC_CMD_ERR;
        goto err_out;
    }

    SET_REE_HDR(&resp->hdr, reply_type, TEE_OK, cmd_len);

    /* copy data from ipc shared memory after IPC */
    THREAD_MEMORY_RELEASE();

    /* copy random number from shared buffer*/
    memcpy(resp->response, ipc, RNG_SIZE_IN_BYTES);

    return 0;

err_out:
    free(*reply_msg);
    *reply_msg = NULL;

    SET_REE_HDR(reply_err, reply_type, err, REE_HDR_LEN);

    return err;
}

/* ree_tee_msg_fn:
 *     For succesfull operation function allocates memory for reply_msg.
 *     Otherwise function sets err_msg and frees all allocated memory
 */
static int ree_tee_deviceid_req(struct ree_tee_hdr *ree_msg __attribute__((unused)),
                                 struct ree_tee_hdr **reply_msg,
                                 struct ree_tee_hdr *reply_err)
{
    int err = -1;
    int32_t reply_type = REE_TEE_DEVICEID_RESP;
    size_t cmd_len = sizeof(struct ree_tee_deviceid_cmd);

    seL4_Word sel4_req = IPC_CMD_SYS_CTL_DEVICEID_REQ;
    seL4_Word sel4_resp = 0;

    struct ree_tee_deviceid_cmd *ipc = (struct ree_tee_deviceid_cmd *)app_shared_memory;
    struct ree_tee_deviceid_cmd *resp = NULL;

    ZF_LOGI("%s", __FUNCTION__);

    *reply_msg = malloc(cmd_len);
    if (!*reply_msg) {
        err = TEE_OUT_OF_MEMORY;
        goto err_out;
    }

    resp = (struct ree_tee_deviceid_cmd *)*reply_msg;

    /* header only, no params for req */

    /*call to sys app*/
    ZF_LOGI("Send msg to sys app...");

    err = ipc_msg_call(ipc_app_ep1,
                       SINGLE_WORD_MSG,
                       &sel4_req,
                       IPC_CMD_SYS_CTL_DEVICEID_RESP,
                       SINGLE_WORD_MSG,
                       &sel4_resp);

    if (err) {
        ZF_LOGE("ERROR ipc_msg_call: %d", err);
        err = TEE_IPC_CMD_ERR;
        goto err_out;
    }

    SET_REE_HDR(&resp->hdr, reply_type, TEE_OK, cmd_len);

    /* copy data from ipc shared memory after IPC */
    THREAD_MEMORY_RELEASE();

    /* copy device id from shared buffer*/
    memcpy(resp->response, ipc, DEVICE_ID_LENGTH);

    return 0;

err_out:
    free(*reply_msg);
    *reply_msg = NULL;

    SET_REE_HDR(reply_err, reply_type, err, REE_HDR_LEN);

    return err;
}

/* ree_tee_msg_fn:
 *     For succesfull operation function allocates memory for reply_msg.
 *     Otherwise function sets err_msg and frees all allocated memory
 */
static int ree_tee_optee_cmd_req(struct ree_tee_hdr *ree_msg,
                               struct ree_tee_hdr **reply_msg,
                               struct ree_tee_hdr *reply_err)
{
    int err = -1;

    struct ipc_msg_gen_payload sel4_req = { 0 };
    struct ipc_msg_gen_payload sel4_resp = { 0 };

    /* REE messages */
    int32_t reply_type = REE_TEE_OPTEE_CMD_RESP;
    uint32_t reply_len = 0;
    int msg_err = TEE_NOK;
    struct ree_tee_optee_cmd *req = (struct ree_tee_optee_cmd *)ree_msg;
    struct ree_tee_optee_cmd *resp = NULL;

    /* Shared Memory */
    uint8_t *ipc_payload = (uint8_t*)app_shared_memory;
    uint32_t payload_len = ree_msg->length - REE_HDR_LEN;

    ZF_LOGI("%s", __FUNCTION__);

    if (ree_msg->length < sizeof(struct ree_tee_optee_cmd)) {
        ZF_LOGE("Invalid Message size");
        msg_err = TEE_INVALID_MSG_SIZE;
        err = -EINVAL;
        goto err_out;
    }

    if (payload_len > app_shared_len) {
        ZF_LOGE("Payload overflow: %d / %d", payload_len, app_shared_len);
        msg_err = TEE_PAYLOAD_OVERFLOW;
        err = -EFBIG;
        goto err_out;
    }

    /* Setup IPC data */
    memcpy(ipc_payload, &req->cmd, payload_len);

    /* Copy data to ipc shared memory before seL4_Call.
     * Using sel4_resp.payload_size-value as reply_len
     * should provide ordering for memcpy following IPC.
     */
    THREAD_MEMORY_RELEASE();

    ZF_LOGI("OPTEE cmd");

    sel4_req.cmd_id = IPC_CMD_OPTEE_REQ;
    sel4_req.payload_size = payload_len;

    err = ipc_msg_call(ipc_app_ep1,
                       IPC_CMD_WORDS(sel4_req),
                       (seL4_Word *)&sel4_req,
                       IPC_CMD_OPTEE_RESP,
                       IPC_CMD_WORDS(sel4_resp),
                       (seL4_Word *)&sel4_resp);

    if (err) {
        ZF_LOGE("ERROR ipc_msg_call: %d", err);
        msg_err = TEE_IPC_CMD_ERR;
        goto err_out;
    }

    /* Allocate memory for resp msg */
    reply_len = sizeof(struct ree_tee_optee_cmd) + sel4_resp.payload_size;

    resp = calloc(1, reply_len);
    if (!resp) {
        ZF_LOGE("out of memory");
        msg_err = TEE_OUT_OF_MEMORY;
        err = -ENOMEM;
        goto err_out;
    }

    memcpy(&resp->cmd, ipc_payload, sel4_resp.payload_size);

    SET_REE_HDR(&resp->hdr, reply_type, TEE_OK, reply_len);

    ZF_LOGI("Message Length = %d", reply_len);

    *reply_msg = (struct ree_tee_hdr *)resp;

    return 0;

err_out:
    free(resp);

    SET_REE_HDR(reply_err, reply_type, msg_err, REE_HDR_LEN);

    return err;
}

/* ree_tee_msg_fn:
 *     For succesfull operation function allocates memory for reply_msg.
 *     Otherwise function sets err_msg and frees all allocated memory
 */
static int ree_tee_optee_init_req(struct ree_tee_hdr *ree_msg __attribute__((unused)),
                                  struct ree_tee_hdr **reply_msg,
                                  struct ree_tee_hdr *reply_err)
{
    int err = -1;

    seL4_Word ipc_req = IPC_CMD_OPTEE_INIT_REQ;
    seL4_Word ipc_resp = 0;

    int32_t reply_type = REE_TEE_OPTEE_INIT_RESP;

    ZF_LOGI("%s", __FUNCTION__);

    err = ipc_msg_call(ipc_app_ep1,
                       SINGLE_WORD_MSG,
                       &ipc_req,
                       IPC_CMD_OPTEE_INIT_RESP,
                       SINGLE_WORD_MSG,
                       (seL4_Word *)&ipc_resp);

    if (err) {
        ZF_LOGF("ERROR ipc_msg_call: %d", err);
        return err;
    }

    *reply_msg = malloc(sizeof(struct ree_tee_hdr));
    if (!*reply_msg) {
        SET_REE_HDR(reply_err, reply_type, TEE_OUT_OF_MEMORY, REE_HDR_LEN);
        return TEE_OUT_OF_MEMORY;
    }

    SET_REE_HDR(*reply_msg, reply_type, TEE_OK, sizeof(struct ree_tee_hdr));

    return 0;
}

/* ree_tee_msg_fn:
 *     For succesfull operation function allocates memory for reply_msg.
 *     Otherwise function sets err_msg and frees all allocated memory
 */
static int ree_tee_optee_storage(struct ree_tee_hdr *ree_msg,
                               struct ree_tee_hdr **reply_msg,
                               struct ree_tee_hdr *reply_err,
                               int32_t ree_reply_type,
                               seL4_Word ipc_cmd_id,
                               seL4_Word ipc_resp_id)
{
    int err = -1;

    struct ipc_msg_gen_payload sel4_req = {
        .cmd_id = ipc_cmd_id,
     };
    struct ipc_msg_gen_payload sel4_resp = { 0 };

    /* REE messages */
    uint32_t reply_len = 0;
    int msg_err = TEE_NOK;
    struct ree_tee_optee_storage_cmd *req = (struct ree_tee_optee_storage_cmd *)ree_msg;
    struct ree_tee_optee_storage_cmd *resp = NULL;

    /* Shared Memory */
    uint8_t *ipc_payload = (uint8_t*)app_shared_memory;
    uint32_t payload_len = ree_msg->length - REE_HDR_LEN;

    if (ree_msg->length < sizeof(struct ree_tee_optee_storage_cmd)) {
        ZF_LOGE("Invalid Message size");
        msg_err = TEE_INVALID_MSG_SIZE;
        err = -EINVAL;
        goto err_out;
    }

    if (payload_len > app_shared_len) {
        ZF_LOGE("Payload overflow: %d / %d", payload_len, app_shared_len);
        msg_err = TEE_PAYLOAD_OVERFLOW;
        err = -EFBIG;
        goto err_out;
    }

    /* Setup IPC data */
    memcpy(ipc_payload, &req->storage, payload_len);

    /* Copy data to ipc shared memory before seL4_Call.
     * Using sel4_resp.payload_size-value as reply_len
     * should provide ordering for memcpy following IPC.
     */
    THREAD_MEMORY_RELEASE();

    sel4_req.payload_size = payload_len;

    err = ipc_msg_call(ipc_app_ep1,
                       IPC_CMD_WORDS(sel4_req),
                       (seL4_Word *)&sel4_req,
                       ipc_resp_id,
                       IPC_CMD_WORDS(sel4_resp),
                       (seL4_Word *)&sel4_resp);

    if (err) {
        ZF_LOGE("ERROR ipc_msg_call: %d", err);
        msg_err = TEE_IPC_CMD_ERR;
        goto err_out;
    }

    /* Allocate memory for resp msg */
    reply_len = REE_HDR_LEN + sel4_resp.payload_size;

    resp = calloc(1, reply_len);
    if (!resp) {
        ZF_LOGE("out of memory");
        msg_err = TEE_OUT_OF_MEMORY;
        err = -ENOMEM;
        goto err_out;
    }

    memcpy(&resp->storage, ipc_payload, sel4_resp.payload_size);

    SET_REE_HDR(&resp->hdr, ree_reply_type, TEE_OK, reply_len);

    ZF_LOGI("Message Length = %d", reply_len);

    *reply_msg = (struct ree_tee_hdr *)resp;

    return 0;

err_out:
    free(resp);

    SET_REE_HDR(reply_err, ree_reply_type, msg_err, REE_HDR_LEN);

    return err;
}

/* ree_tee_msg_fn:
 *     For succesfull operation function allocates memory for reply_msg.
 *     Otherwise function sets err_msg and frees all allocated memory
 */

static int ree_tee_optee_export_storage_req(struct ree_tee_hdr *ree_msg,
                               struct ree_tee_hdr **reply_msg,
                               struct ree_tee_hdr *reply_err)
{
    ZF_LOGI("REE_TEE_OPTEE_EXPORT_STORAGE_REQ");

    return ree_tee_optee_storage(ree_msg, reply_msg, reply_err,
                                 REE_TEE_OPTEE_EXPORT_STORAGE_RESP,
                                 IPC_CMD_OPTEE_EXPORT_REQ,
                                 IPC_CMD_OPTEE_EXPORT_RESP);
}

/* ree_tee_msg_fn:
 *     For succesfull operation function allocates memory for reply_msg.
 *     Otherwise function sets err_msg and frees all allocated memory
 */
static int ree_tee_optee_import_storage_req(struct ree_tee_hdr *ree_msg,
                               struct ree_tee_hdr **reply_msg,
                               struct ree_tee_hdr *reply_err)
{
    ZF_LOGI("REE_TEE_OPTEE_IMPORT_STORAGE_REQ");

    return ree_tee_optee_storage(ree_msg, reply_msg, reply_err,
                                 REE_TEE_OPTEE_IMPORT_STORAGE_RESP,
                                 IPC_CMD_OPTEE_IMPORT_REQ,
                                 IPC_CMD_OPTEE_IMPORT_RESP);
}

static int handle_rpmsg_msg(struct ree_tee_hdr *ree_msg,
                            struct ree_tee_hdr **reply_msg,
                            struct ree_tee_hdr *reply_err)
{
    int err = -1;

    ree_tee_msg_fn msg_fn = NULL;

    ZF_LOGI("msg type: %d, len: %d", ree_msg->msg_type, ree_msg->length);

    /* Find msg handler callback */
    for (int i = 0; i < (ssize_t)FN_LIST_LEN(ree_tee_fn); i++) {
        /* Check if msg type is found from callback list */
        if (ree_tee_fn[i][0] != (uint32_t)ree_msg->msg_type) {
            continue;
        }

        /* Call msg handler function */
        msg_fn = (ree_tee_msg_fn)ree_tee_fn[i][1];
        err = msg_fn(ree_msg, reply_msg, reply_err);
        if (err) {
            ZF_LOGE("ERROR msg_fn: %d", err);
        }
        break;
    }

    /* Unknown message */
    if (!msg_fn) {
        ZF_LOGE("ERROR unknown msg: %d", ree_msg->msg_type);
        err = TEE_UNKNOWN_MSG;

        /* Use received unknown msg type in response */
        SET_REE_HDR(reply_err, ree_msg->msg_type, err, REE_HDR_LEN);
    }

    return err;
}

static int wait_ree_rpmsg_msg()
{
    int err = -1;
    char *msg = NULL;
    uint32_t msg_len = 0;
    struct ree_tee_hdr *reply = NULL;
    struct ree_tee_hdr err_msg = { 0 };

    struct ree_tee_hdr *send_msg = NULL;

    while (1) {
        ZF_LOGV("waiting REE msg...");

        /* function allocates memory for msg */
        err = rpmsg_wait_ree_msg(&msg, &msg_len);
        if (err) {
            ZF_LOGE("ERROR rpmsg_wait_ree_msg: %d", err);

            /* try to send error response, best effort only */
            SET_REE_HDR(&err_msg, REE_TEE_STATUS_RESP, err, REE_HDR_LEN);
            rpmsg_send_ree_msg((char *)&err_msg, err_msg.length);

            continue;
        }

        /* function allocates memory for reply or returns err_msg */
        err = handle_rpmsg_msg((struct ree_tee_hdr*)msg, &reply, &err_msg);

        if (err) {
            ZF_LOGE("ERROR handle_rpmsg_msg: %d", err);
            send_msg = &err_msg;
        } else {
            send_msg = reply;
        }

        /* msg buffer not needed anymore */
        free(msg);
        msg = NULL;

        ZF_LOGV("resp type %d, len %d", send_msg->msg_type, send_msg->length);

        err = rpmsg_send_ree_msg((char *)send_msg, send_msg->length);
        if (err) {
            /* These are more or less fatal errors, abort*/
            ZF_LOGF("ERROR rpmsg_send_ree_msg: %d", err);
            return err;
        }

        free(reply);
        reply = NULL;
    }

    return err;
}


static void recv_from_app(void)
{
    seL4_MessageInfo_t msg_info = {0};
    seL4_Word msg_len = 0;
    seL4_Word sender_badge = 0;
    seL4_Word msg_data = 0;

    ZF_LOGV("Wait msg from app...");
    msg_info = seL4_Recv(ipc_app_ep1, &sender_badge);
    msg_len = seL4_MessageInfo_get_length(msg_info);

    if (msg_len > 0) {
        msg_data = seL4_GetMR(0);
    }

    ZF_LOGV("msg from 0x%lx (%ld) 0x%lx", sender_badge, msg_len, msg_data);

    msg_info = seL4_MessageInfo_new(0, 0, 0, 1);
    msg_data++;
    seL4_SetMR(0, msg_data);

    seL4_Reply(msg_info);
}


int main(int argc, char **argv)
{
    int error = -1;

    ZF_LOGI("%s", CONFIG_TEE_COMM_APP_NAME);
    seL4_DebugNameThread(SEL4UTILS_TCB_SLOT, CONFIG_TEE_COMM_APP_NAME);

    if (argc != 1) {
        ZF_LOGF("Invalid arg count: %d", argc);
        return -EINVAL;
    }

    ipc_root_ep = (seL4_CPtr)atol(argv[0]);
    if (ipc_root_ep == 0) {
        ZF_LOGF("Invalid root endpoint");
        return -EFAULT;
    }

    ZF_LOGI("ipc_root_ep: %p", (void *)ipc_root_ep);

    /* Wait crashlog config from rootserver */
    error = setup_crashlog();
    if (error) {
        return error;
    }

    /* Wait app shared memory config from rootserver */
    error = setup_comm_ch();
    if (error) {
        return error;
    }

    /* Wait rpmsg config from rootserver */
    error = setup_ihc_buf(&comm.rpmsg_conf);
    if (error) {
        return error;
    }

    error = setup_app_ep();
    if (error) {
        return error;
    }

    /* Ping-pong IPC */
    recv_from_app();

    /* Create RPMSG remote endpoint and wait for master to come online */
    error = rpmsg_create_sel4_ept(&comm.rpmsg_conf);
    if (error) {
        return error;
    }

    /* Announce RPMSG TTY endpoint to linux */
    error = rpmsg_announce_sel4_ept();
    if (error) {
        return error;
    }

    error = wait_ree_rpmsg_msg();

    return error;
}