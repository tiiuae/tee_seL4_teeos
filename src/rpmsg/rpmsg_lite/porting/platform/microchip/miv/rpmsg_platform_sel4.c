/*
 * Copyright 2016-2019 NXP
 * Copyright 2019-2021 Microchip FPGA Embedded Systems Solutions.
 * Copyright 2021 Unikie
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sel4_teeos/gen_config.h>
#include <sel4runtime.h>
#include "rpmsg_platform.h"
#include "rpmsg_env.h"

#include "rpmsg_sel4.h"

#include "linux/dt-bindings/mailbox/miv-ihc.h"
#include "linux/mailbox/miv_ihc_message.h"

#include "sel4_ihc.h"

/* Local log level */
#define ZF_LOG_LEVEL ZF_LOG_ERROR
#include <utils/util.h>
#include <utils/zf_log.h>

static struct sel4_rpmsg_config *sel4_config = NULL;

#define UNUSED_PARAM        0

static void *platform_lock = NULL;

/* From linux/drivers/mailbox/mailbox-miv-ihc.c */
enum {
    SBI_EXT_IHC_INIT = 0x0,
    SBI_EXT_IHC_TX = 0x1,
    SBI_EXT_IHC_RX = 0x2,
};

static int32_t isr_counter     = 0;

int32_t platform_init_interrupt(uint32_t vector_id, void *isr_data)
{
    int err = -1;

    if (!sel4_config) {
        ZF_LOGE("Config uninitialized");
        return RL_NOT_READY;
    }

    /* Register ISR to environment layer */
    env_register_isr(vector_id, isr_data);

    /* Ack the handler so interrupts can come in */
    err = sel4_config->irq_handler_ack(sel4_config->ihc_irq);
    if (err) {
        ZF_LOGF("IRQ ack failed: %d", err);
        return RL_NOT_READY;
    }

    return 0;
}

int32_t platform_deinit_interrupt(uint32_t vector_id)
{
    /* Unregister ISR from environment layer */
    env_unregister_isr(vector_id);

    return 0;
}

void platform_notify(uint32_t vector_id)
{
    struct miv_ihc_msg tx = { 0 };

    if (!sel4_config) {
        ZF_LOGE("Config uninitialized");
        return;
    }

    env_lock_mutex(platform_lock);

    tx.msg[0] = (uint32_t)(vector_id << 16);

    sel4_ihc_ree_tx(&tx);

    env_unlock_mutex(platform_lock);
}

static uint64_t riscv_read_time(void)
{
    uint64_t n;
    asm volatile(
        "rdtime %0"
        : "=r"(n));
    return n;
}

/**
 * platform_time_delay
 *
 * @param num_msec Delay time in ms.
 *
 * This is not an accurate delay, it ensures at least num_msec passed when return.
 */
void platform_time_delay(uint32_t num_msec)
{
    uint64_t start = riscv_read_time();

    while (riscv_read_time() - start < ((CONFIG_HW_TIMER_FREQ / 1000UL) * num_msec)) {
        seL4_Yield();
    }
}

/**
 * platform_interrupt_enable
 *
 * Enable peripheral-related interrupt
 *
 * @param vector_id Virtual vector ID that needs to be converted to IRQ number
 *
 * @return vector_id Return value is never checked.
 *
 */
int32_t platform_interrupt_enable(uint32_t vector_id)
{
    /* No need to enable/disable irq. Pending interrupt status
     * is read via syscall */
    return ((int32_t)vector_id);
}

/**
 * platform_interrupt_disable
 *
 * Disable peripheral-related interrupt.
 *
 * @param vector_id Virtual vector ID that needs to be converted to IRQ number
 *
 * @return vector_id Return value is never checked.
 *
 */
int32_t platform_interrupt_disable(uint32_t vector_id)
{
    /* No need to enable/disable irq. Pending interrupt status
     * is read via syscall */
    return ((int32_t)vector_id);
}

/**
 * platform_vatopa
 *
 * Dummy implementation
 *
 */
uint32_t platform_vatopa(void *addr)
{
    int64_t offset = 0;
    int64_t va = (int64_t)addr;
    int64_t pa = 0;

    if (!sel4_config)
        return 0x0;

    offset = (int64_t)sel4_config->vring_pa - (int64_t)sel4_config->vring_va;

    pa = va + offset;


    return (uint32_t)(va + offset);
}

/**
 * platform_patova
 *
 * Dummy implementation
 *
 */
void *platform_patova(uint32_t addr)
{
    int64_t offset = 0;
    int64_t pa = addr;

    if (!sel4_config)
        return NULL;

    offset = (int64_t)sel4_config->vring_va - (int64_t)sel4_config->vring_pa;

    return (void *)(pa + offset);
}

/**
 * platform_init_sel4
 *
 * Initialize seL4 specific platform/environment.
 * Must be run before platform_init.
 */
void platform_init_sel4(void *config)
{
    sel4_config = (struct sel4_rpmsg_config *)config;
}

/**
 * platform_init
 *
 * platform/environment init
 */
int32_t platform_init(void)
{
    int32_t err = -1;

    if (!sel4_config) {
        return RL_NOT_READY;
    }

    /* Create lock used in multi-instanced RPMsg */
    err = env_create_mutex(&platform_lock, UNUSED_PARAM);
    if (err)
        return err;

    /* Init FPGA IHC */
    err = sel4_ihc_setup_ch_to_ree();
    if (err) {
        return err;
    }

    return err;
}

/**
 * platform_deinit
 *
 * platform/environment deinit process
 */
int32_t platform_deinit(void)
{
    /* Delete lock used in multi-instanced RPMsg */
    env_delete_mutex(platform_lock);
    platform_lock = ((void *)0);
    return 0;
}

static int platform_ihc_get_next(struct sel4_rpmsg_config *config, uint32_t *ihc)
{
    int res = -1;

    uint32_t irq_type = 0;
    struct miv_ihc_msg ihc_msg = { 0 };

    uint32_t vring_idx = 0;

    res = sel4_ihc_ree_rx(&irq_type, &ihc_msg);
    /* Interrupts cleared, but no IHC message recveived -> NOP */
    if (res == -ENXIO) {
        *ihc = IHC_CALL_NOP;
        return 0;
    }

    if (res) {
        return res;
    }

    if (irq_type == IHC_MP_IRQ) {
        ZF_LOGI("IHC_MP_IRQ: [0x%x 0x%x]", ihc_msg.msg[0], ihc_msg.msg[1]);

        vring_idx = ihc_msg.msg[0];
        env_isr((uint32_t)(vring_idx >> 16));
        *ihc = IHC_CALL_MP;

    } else { /* IHC_ACK_IRQ */
        *ihc = IHC_CALL_ACK;
    }

    return res;
}

int platform_wait_ihc(uint32_t *ihc_type)
{
    seL4_Word badge = 0;
    int err = -1;
    uint32_t ihc = IHC_CALL_INVALID;

    if (!sel4_config) {
        ZF_LOGE("Config uninitialized");
        return RL_NOT_READY;
    }

    sel4_config->irq_notify_wait(sel4_config->ihc_ntf, &badge);

    err = platform_ihc_get_next(sel4_config, &ihc);
    if (err) {
        return RL_NOT_READY;
    }

    if (ihc_type) {
        *ihc_type = ihc;
    }

    /* Ack the handler so interrupts can come in */
    err = sel4_config->irq_handler_ack(sel4_config->ihc_irq);
    if (err) {
        ZF_LOGE("seL4_IRQHandler_Ack failed: %d", err);
        return RL_NOT_READY;
    }

    return RL_SUCCESS;
}
