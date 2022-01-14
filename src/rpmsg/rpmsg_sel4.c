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
