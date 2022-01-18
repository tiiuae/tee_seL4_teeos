/*
 * Copyright 2021, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#pragma once

#include <sel4/types.h>

#include "rpmsg_lite.h"
#include "rpmsg_queue.h"
#include "rpmsg_ns.h"

#define IHC_IRQ_BADGE               IHC_HART4_INT

#define RPMSG_RX_MAX_BUFF_SIZE      256U
#define RPMSG_SEL4_EPT_ADDR         6U
#define RPMSG_TTY_CHANNEL_NAME      "rpmsg-virtual-tty-channel"


struct sel4_rpmsg_config {
    uintptr_t ihc_buf_pa;
    void *ihc_buf_va;

    seL4_CPtr ihc_irq;
    seL4_CPtr ihc_ntf;

    void *vring_va;
    uintptr_t vring_pa;
};

int rpmsg_create_sel4_ept(struct sel4_rpmsg_config *config);
int rpmsg_announce_sel4_ept();