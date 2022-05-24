/*
 * Copyright 2021, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#pragma once

#include <sel4/types.h>
#include <sel4/errors.h>

#include "rpmsg_lite.h"
#include "rpmsg_queue.h"
#include "rpmsg_ns.h"

#define IHC_IRQ_BADGE               IHC_HART4_INT

#define RPMSG_RX_MAX_BUFF_SIZE      256U
#define RPMSG_SEL4_EPT_ADDR         6U
#define RPMSG_TTY_CHANNEL_NAME      "rpmsg-virtual-tty-channel"

typedef seL4_Error (*sel4_irq_handler_ack_fn)(seL4_IRQHandler _service);
typedef void (*sel4_wait_fn)(seL4_CPtr src, seL4_Word *sender);

struct sel4_rpmsg_config {
    seL4_CPtr ihc_irq;
    seL4_CPtr ihc_ntf;

    void *ihc_reg_base;

    sel4_wait_fn            irq_notify_wait;
    sel4_irq_handler_ack_fn irq_handler_ack;

    void *vring_va;
    uintptr_t vring_pa;
};

int rpmsg_create_sel4_ept(struct sel4_rpmsg_config *config);
int rpmsg_announce_sel4_ept();
int rpmsg_wait_ree_msg(char **msg, uint32_t *msg_len);
int rpmsg_send_ree_msg(char *msg, uint32_t msg_len);
