/*
 * Copyright 2022, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "sel4_ihc.h"

#include <sel4_teeos/gen_config.h>

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>

#include <sel4runtime.h>

/* Local log level */
#define ZF_LOG_LEVEL    ZF_LOG_ERROR
#include <utils/fence.h>
#include <utils/zf_log.h>

#include "miv_ihc.h"
#include "miv_ihc_config.h"

#define IHC_RX_MP_MASK      0x1UL
#define IHC_RX_ACK_MASK     0x2UL

static struct ihc_reg_cluster *sel4_ihc = NULL;

/* As described in miv_ihc_regs.h */
struct ihc_reg_cluster
{
    IHC_IP_TypeDef HART_IHC[4];
    IHCIA_IP_TypeDef interrupt_concentrator;
};

static void print_cluster_reg(struct ihc_reg_cluster *hart_reg)
{
    for (int i = 0; i < 4; i++) {
        ZF_LOGI("    IHC[%d]: CTL[0x%x] loc_hart_id[%d] msg_size[%d]",
            i,
            hart_reg->HART_IHC[i].CTR_REG.CTL_REG,
            hart_reg->HART_IHC[i].local_hart_id,
            hart_reg->HART_IHC[i].size_msg);
    }

    ZF_LOGI("    irq_concentr: en[0x%x] msg_avail[0x%x]",
        hart_reg->interrupt_concentrator.INT_EN.INT_EN,
        hart_reg->interrupt_concentrator.MSG_AVAIL_STAT.MSG_AVAIL);
}

void sel4_ihc_reg_print()
{
    struct ihc_reg_cluster *ree_ihc = NULL;

    if (!sel4_ihc) {
        ZF_LOGE("ERROR: init failure");
        return;
    }

    ZF_LOGI("sel4 IHC cluster [%d]: %p", IHC_SEL4_HART_ID, sel4_ihc);

    print_cluster_reg(sel4_ihc);

    ree_ihc = sel4_ihc - 3;

    ZF_LOGI("REE IHC cluster [%d]: %p", IHC_REE_HART_ID, ree_ihc);

    print_cluster_reg(ree_ihc);
}

int sel4_ihc_setup_ch_to_ree()
{
    if (!sel4_ihc) {
        ZF_LOGE("ERROR: invalid parameter");
        return -EPERM;
    }

    sel4_ihc->interrupt_concentrator.INT_EN.INT_EN = IHCIA_H4_REMOTE_HARTS_INTS;

    sel4_ihc->HART_IHC[IHC_REE_HART_ID].CTR_REG.CTL_REG |= MPIE_EN;

    sel4_ihc->HART_IHC[IHC_REE_HART_ID].CTR_REG.CTL_REG |= ACKIE_EN;

    ZF_LOGI("INT_EN: 0x%x, CTL_REG: 0x%x",
        sel4_ihc->interrupt_concentrator.INT_EN.INT_EN,
        sel4_ihc->HART_IHC[IHC_REE_HART_ID].CTR_REG.CTL_REG);

    return 0;
}

static int get_ree_ihc(uint32_t *sender, uint32_t *irq_type, struct miv_ihc_msg *ihc_msg)
{
    uint32_t msg_avail = sel4_ihc->interrupt_concentrator.MSG_AVAIL_STAT.MSG_AVAIL;
    uint32_t ctl_reg = 0;

    uint32_t irq_ack = 0;
    uint32_t irq_mp = 0;

    int32_t hart_id = -1;

    /*
     * Find hart which has sent ack or msg.
     * Bitfield described in IHCA_IP_MSG_AVAIL_STAT_TypeDef.
     */
    for (unsigned int i = 0; i <= HART4_ID; i++) {
        irq_ack = msg_avail & (IHC_RX_ACK_MASK << i * 2);
        irq_mp = msg_avail & (IHC_RX_MP_MASK << i * 2);

        if (irq_ack || irq_mp) {
            hart_id = i;
            break;
        }
    }

    if (hart_id == -1) {
        ZF_LOGI("No IHC sender found");
        return -ENXIO;
    }

    if (irq_ack) {
        ZF_LOGI("IHC_ACK_IRQ [%d]", hart_id);

        /* clear the ack */
        sel4_ihc->HART_IHC[hart_id].CTR_REG.CTL_REG &= ~ACK_CLR;

        *sender = hart_id;
        *irq_type = IHC_ACK_IRQ;

    } else { /* irq_mp */
        ZF_LOGI("IHC_MP_IRQ [%d]", hart_id);

        ctl_reg = sel4_ihc->HART_IHC[hart_id].CTR_REG.CTL_REG;

        /* no message after all */
        if (!(ctl_reg & MP_MESSAGE_PRESENT)) {
            ZF_LOGI("IHC no message");
            return -ENXIO;
        }

        memcpy(ihc_msg->msg,
            (uint32_t *)sel4_ihc->HART_IHC[hart_id].mesg_in,
            sel4_ihc->HART_IHC[hart_id].size_msg * sizeof(uint32_t));

        /* copy data from IHC buffer before ACK to sender */
        COMPILER_MEMORY_RELEASE();

        /* clear the MP bit */
        ctl_reg &= ~MP_MESSAGE_PRESENT;

        /* ACK the sender */
        if (ctl_reg & ACKIE_EN) {
            ctl_reg |= ACK_INT;
            ZF_LOGI("ACKIE_EN");
        }

        sel4_ihc->HART_IHC[hart_id].CTR_REG.CTL_REG = ctl_reg;

        *sender = hart_id;
        *irq_type = IHC_MP_IRQ;
    }

    return 0;
}

/* return -ENXIO if IHC was not from REE */
int sel4_ihc_ree_rx(uint32_t *irq_type, struct miv_ihc_msg *ihc_msg)
{
    int err = -1;

    uint32_t sender = 0;
    uint32_t irq = 0;
    struct miv_ihc_msg msg = { 0 };

    if (!sel4_ihc) {
        ZF_LOGE("ERROR: init failure");
        return -EPERM;
    }

    err = get_ree_ihc(&sender, &irq, &msg);
    if (err) {
        return err;
    }

    if (sender == IHC_REE_HART_ID) {
        *irq_type = irq;
        memcpy(ihc_msg, &msg, sizeof(msg));
    } else { /* NOP IHC */
        err = -ENXIO;
        ZF_LOGI("IHC NOP [%d]", sender);
    }

    return err;
}

void sel4_ihc_ree_tx(struct miv_ihc_msg *ihc_msg)
{
    volatile uint32_t ctl_reg = sel4_ihc->HART_IHC[IHC_REE_HART_ID].CTR_REG.CTL_REG;

    /* wait until target has processed previous IHC */
    while (ctl_reg & RMP_MESSAGE_PRESENT ||
        ctl_reg & ACK_INT_MASK) {
        ctl_reg = sel4_ihc->HART_IHC[IHC_REE_HART_ID].CTR_REG.CTL_REG;
    }

    /* Target must finnish ongoing IHC before a new msg can be copied */
    COMPILER_MEMORY_RELEASE();

    memcpy((void *)sel4_ihc->HART_IHC[IHC_REE_HART_ID].mesg_out,
           ihc_msg,
           sel4_ihc->HART_IHC[IHC_REE_HART_ID].size_msg * sizeof(uint32_t));

    /* copy data to IHC buffer before raising IRQ to target */
    COMPILER_MEMORY_RELEASE();

    /* Set the MP bit. This will notify other of incoming hart message */
    sel4_ihc->HART_IHC[IHC_REE_HART_ID].CTR_REG.CTL_REG |= RMP_MESSAGE_PRESENT;
}

int sel4_ihc_init(void *ihc_reg_base)
{
    struct ihc_reg_cluster *ihc_reg = NULL;

    if (!ihc_reg_base) {
        ZF_LOGE("ERROR: invalid parameter");
        return -EINVAL;
    }

    ihc_reg = (struct ihc_reg_cluster *)ihc_reg_base;
    sel4_ihc = &ihc_reg[IHC_SEL4_HART_ID];

    ZF_LOGI("ihc_reg_base: %p", ihc_reg_base);
    ZF_LOGI("sel4_ihc:     %p", sel4_ihc);

    return 0;
}
