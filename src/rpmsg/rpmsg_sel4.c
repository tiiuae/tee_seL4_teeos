/*******************************************************************************
 * Copyright 2019-2021 Microchip FPGA Embedded Systems Solutions.
 * Copyright 2022 Unikie
 *
 * SPDX-License-Identifier: MIT
 *
 * Application code
 *
 * Ported to seL4 from FreeRTOS example project suitable for
 * Asymmetric Multiprocessing (AMP) configuration
 *
 */
/*******************************************************************************/

#include <string.h>
#include <sel4runtime.h>
#include "rpmsg_config.h"
#include "rpmsg_sel4.h"
#include "rpmsg_platform.h"
#include "ree_tee_msg.h"

/* Local log level */
#define ZF_LOG_LEVEL ZF_LOG_INFO
#include <utils/util.h>
#include <utils/zf_log.h>

#define UNUSED_VALUE                NULL

static struct sel4_rpmsg_config *rpmsg_config = NULL;

/* polarfire-soc-amp-examples/mpfs-rpmsg-freertos/src/application/inc/demo_main.h */
struct rpmsg_comm_stack
{
    struct rpmsg_lite_endpoint *ctrl_ept;
    rpmsg_queue_handle ctrl_q;
    struct rpmsg_lite_instance *rpmsg_dev;
    rpmsg_ns_handle ns_handle;
    volatile uint32_t master_addr;
    char *in_buf;
    uint32_t in_buf_len;
};

static struct rpmsg_comm_stack rpmsg_instance = { 0 };

/* Code ported from:
 *     polarfire-soc-amp-examples/mpfs-rpmsg-freertos/
 *         src/application/inc/demo_main.c: rpmsg_setup()
 *
 *     polarfire-soc-amp-examples/mpfs-rpmsg-freertos/
 *         src/application/inc/sample_echo_demo.c: rpmsg_echo_demo_setup()
 */
static int rpmsg_setup(struct rpmsg_comm_stack *handle,
                       struct sel4_rpmsg_config *config)
{
    int err = -1;

    /* Set seL4 config before runnig rpmsg_lite_remote_init ()*/
    platform_init_sel4(config);

    ZF_LOGI("vring va: %p", config->vring_va);

    handle->master_addr = 0xFFFFFFFF;

    /* RPMsg Remote Mode */
    handle->rpmsg_dev =
        rpmsg_lite_remote_init(config->vring_va,
                               RL_PLATFORM_MIV_IHC_CONTEXT_A_B_LINK_ID,
                               RL_NO_FLAGS);
    if (!handle->rpmsg_dev) {
        ZF_LOGF("ERROR: rpmsg_lite_remote_init");
        return RL_NOT_READY;
    }

    handle->ctrl_q = rpmsg_queue_create(handle->rpmsg_dev);
    if (!handle->ctrl_q) {
        ZF_LOGF("ERROR: rpmsg_queue_create");
        return RL_ERR_DEV_ID;
    }

    ZF_LOGI("waiting RPMSG master...");
    while(!rpmsg_lite_is_link_up(handle->rpmsg_dev))
    {
        err = platform_wait_ihc(UNUSED_VALUE);
        if (err) {
            ZF_LOGF("ERROR: platform_wait_ihc: %d", err);
            return err;
        }
    }

    ZF_LOGI("RPMSG master ready");

    if (rpmsg_queue_get_current_size(handle->ctrl_q) > 0) {
        ZF_LOGF("ERROR: queue not empty");
        return RL_ERR_MAX_VQ;
    }

    handle->ctrl_ept =
            rpmsg_lite_create_ept(handle->rpmsg_dev,
                                RPMSG_SEL4_EPT_ADDR,
                                rpmsg_queue_rx_cb,
                                handle->ctrl_q);

    if (!handle->ctrl_ept) {
        ZF_LOGF("ERROR: ctrl_ept");
        return RL_ERR_NO_MEM;
    }

    handle->in_buf = env_allocate_memory(RPMSG_RX_MAX_BUFF_SIZE);
    if (!handle->in_buf) {
        ZF_LOGF("ERROR: in_buf");
        return RL_ERR_NO_MEM;
    }

    handle->in_buf_len = RPMSG_RX_MAX_BUFF_SIZE;

    return err;
}

/* Code ported from:
 *     polarfire-soc-amp-examples/mpfs-rpmsg-freertos/
 *         src/application/inc/sample_echo_demo.c: rpmsg_echo_demo()
 */
static int rpmsg_recv_handshake(struct rpmsg_comm_stack *handle)
{
    int err = -1;
    uint32_t ihc_type = IHC_CALL_INVALID;
    uint32_t sender = 0;
    uint32_t len = 0;

    while (ihc_type != IHC_CALL_MP) {
        err = platform_wait_ihc(&ihc_type);
        if (err) {
            ZF_LOGF("ERROR: platform_wait_ihc: %d", err);
            return err;
        }
    }

    if (rpmsg_queue_get_current_size(handle->ctrl_q) < 1) {
        ZF_LOGF("No handshake msg");
        return RL_NOT_READY;
    }

    memset(handle->in_buf, 0x0, handle->in_buf_len);

    err = rpmsg_queue_recv(handle->rpmsg_dev, handle->ctrl_q, &sender,
                           handle->in_buf, handle->in_buf_len, &len,
                           RL_BLOCK);
    if (err) {
        ZF_LOGF("ERROR recv: %d", err);
        return err;
    }

    ZF_LOGI("src[%d], len[%d]", sender, len);

    handle->master_addr = sender;

    return err;
}

/* Code ported from:
 *     polarfire-soc-amp-examples/mpfs-rpmsg-freertos/
 *         src/application/inc/console_demo.c
 */
static int rpmsg_announce_tty_channel(struct rpmsg_comm_stack *handle)
{
    int err = -1;
    uint32_t ihc_type = IHC_CALL_INVALID;

    err = rpmsg_ns_announce(handle->rpmsg_dev,
                      handle->ctrl_ept,
                      RPMSG_TTY_CHANNEL_NAME,
                      RL_NS_CREATE);
    if (err) {
        return err;
    }

    /* Wait ack from master */
    ZF_LOGI("Wait announce ack from master");

    while (ihc_type != IHC_CALL_ACK) {
        err = platform_wait_ihc(&ihc_type);
        if (err) {
            ZF_LOGF("ERROR: platform_wait_ihc: %d", err);
            return err;
        }
    }

    ZF_LOGI("Wait channel handshake from master...");

    err = rpmsg_recv_handshake(handle);
    if (err) {
        return err;
    }

    return err;
}

static int rpmsg_recv_vring(struct rpmsg_comm_stack *handle, uint32_t *recv)
{
    int err = -1;
    uint32_t sender = 0;
    uint32_t ihc_type = IHC_CALL_INVALID;

    while (ihc_type != IHC_CALL_MP) {
        err = platform_wait_ihc(&ihc_type);
        if (err) {
            ZF_LOGE("ERROR: platform_wait_ihc: %d", err);
            return err;
        }
    }

    if (rpmsg_queue_get_current_size(handle->ctrl_q) < 1) {
        ZF_LOGE("ERROR: virtqueue empty");
        return RL_NOT_READY;
    }

    err = rpmsg_queue_recv(handle->rpmsg_dev, handle->ctrl_q, &sender,
                           handle->in_buf, handle->in_buf_len, recv, RL_BLOCK);
    if (err) {
        ZF_LOGE("ERROR recv: %d", err);
        return err;
    }

    return err;
}

static int rpmsg_next_msg(struct rpmsg_comm_stack *handle, char **recv_cmd, uint32_t *recv_bytes)
{
    int err = -1;
    struct ree_tee_hdr *hdr = (struct ree_tee_hdr *)handle->in_buf;

    uint32_t vring_len = 0;
    uint32_t recv_total = 0;
    uint32_t msg_len = 0;
    char *msg_buf = NULL;

    err = rpmsg_recv_vring(handle, &vring_len);
    if (err) {
        ZF_LOGE("ERROR rpmsg_recv_single_msg: %d", err);
        goto err_out;
    }

    /* At minimum cmd header is required */
    if (vring_len < sizeof(struct ree_tee_hdr) ||
        vring_len > hdr->length) {
        ZF_LOGE("ERROR invalid length: %d", vring_len);
        err = RL_ERR_BUFF_SIZE;
        goto err_out;
    }

    ZF_LOGI("cmd: type[0x%x], len[%d]", hdr->msg_type, hdr->length);

    msg_len = hdr->length;

    /* Reserve memory for whole cmd */
    msg_buf = env_allocate_memory(msg_len);
    if (!msg_buf) {
        ZF_LOGE("ERROR: msg_buf out of memory");
        err = RL_ERR_NO_MEM;
        goto err_out;
    }

    memcpy(msg_buf, handle->in_buf, vring_len);

    recv_total += vring_len;

    /* Receive the rest of cmd */
    while (recv_total < msg_len) {
        err = rpmsg_recv_vring(handle, &vring_len);
        if (err) {
            ZF_LOGE("ERROR rpmsg_recv_single_msg: %d", err);
            goto err_out;
        }

        /* Exactly msg size required, no support for concatenated msgs. */
        if (recv_total + vring_len > msg_len) {
            ZF_LOGE("ERROR invalid cmd size: %d", recv_total + vring_len);
            err = RL_ERR_BUFF_SIZE;
            goto err_out;
        }

        memcpy(msg_buf + recv_total, handle->in_buf, vring_len);
        recv_total += vring_len;

        ZF_LOGV("vring_len[%d], recv_total[%d]", vring_len, recv_total);
    }

    *recv_cmd = msg_buf;
    *recv_bytes = recv_total;

    return 0;

err_out:
    if (msg_buf) {
        env_free_memory(msg_buf);
    }

    return err;
}

int rpmsg_wait_ree_msg(char **msg, uint32_t *msg_len)
{
    int err = -1;
    char *recv = NULL;
    uint32_t recv_len = 0;

    err = rpmsg_next_msg(&rpmsg_instance, &recv, &recv_len);
    if (err) {
        ZF_LOGE("ERROR: rpmsg_next_msg: %d", err);
        return err;
    }

    *msg = recv;
    *msg_len = recv_len;

    return err;
}

int rpmsg_send_ree_msg(char *msg, uint32_t msg_len)
{
    int err = -1;
    struct rpmsg_comm_stack *handle = &rpmsg_instance;
    uint32_t remaining = msg_len;
    uint32_t sent = 0;
    uint32_t len = 0;
    uint32_t ihc_type = IHC_CALL_INVALID;

    while (remaining) {
        /* rpmsg single message max size is RL_BUFFER_PAYLOAD_SIZE */
        len = MIN(remaining, RL_BUFFER_PAYLOAD_SIZE);

        ZF_LOGV("send[%d], remaining[%d]", len, remaining);

        err = rpmsg_lite_send(handle->rpmsg_dev, handle->ctrl_ept,
                    handle->master_addr, msg + sent, len, RL_BLOCK);
        if (err) {
            ZF_LOGF("ERROR rpmsg send: %d", err);
            return err;
        }

        sent += len;
        remaining -= len;

        /* Wait master ack before sending next */
        do {
            err = platform_wait_ihc(&ihc_type);
            if (err) {
                ZF_LOGF("ERROR: platform_wait_ihc: %d", err);
                return err;
            }
        } while (ihc_type != IHC_CALL_ACK);
    }

    return err;
}

int rpmsg_create_sel4_ept(struct sel4_rpmsg_config *config)
{
    int err = -1;

    rpmsg_config = config;

    err = rpmsg_setup(&rpmsg_instance, rpmsg_config);
    if (err) {
        ZF_LOGF("ERROR: rpmsg_setup: %d", err);
        return err;
    }

    return err;
}

int rpmsg_announce_sel4_ept()
{
    int err = -1;

    err = rpmsg_announce_tty_channel(&rpmsg_instance);
    if (err) {
        ZF_LOGF("ERROR: announce channel: %d", err);
        return err;
    }

    return err;
}
