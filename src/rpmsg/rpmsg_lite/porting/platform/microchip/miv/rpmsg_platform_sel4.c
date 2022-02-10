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
#include <teeos/gen_config.h>
#include <sel4runtime.h>
#include "rpmsg_platform.h"
#include "rpmsg_env.h"

#include "rpmsg_sel4.h"

#include "linux/dt-bindings/mailbox/miv-ihc.h"
#include "linux/mailbox/miv_ihc_message.h"

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

    /* Register ISR to environment layer */
    env_register_isr(vector_id, isr_data);

    /* Ack the handler so interrupts can come in */
    err = seL4_IRQHandler_Ack(sel4_config->ihc_irq);
    if (err) {
        ZF_LOGF("seL4_IRQHandler_Ack failed: %d", err);
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
    struct miv_ihc_msg *tx = (struct miv_ihc_msg *)sel4_config->ihc_buf_va;

    env_lock_mutex(platform_lock);

    memset(tx, 0xFF, sizeof(struct miv_ihc_msg));

    tx->msg[0] = (uint32_t)(vector_id << 16);

    /* Init HSS IHC */
    seL4_HssIhcCall(SBI_EXT_IHC_TX, IHC_CONTEXT_A, sel4_config->ihc_buf_pa);

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

    /* Init HSS IHC */
    seL4_HssIhcCall(SBI_EXT_IHC_INIT, IHC_CONTEXT_A, UNUSED_PARAM);

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

static uint32_t platform_ihc_get_next(struct sel4_rpmsg_config *config)
{
    int res = IHC_CALL_NOP;
    struct ihc_sbi_msg *resp = config->ihc_buf_va;
    uint32_t vring_idx = 0;

    /* Clear garbage from recv buffer as non-channel IRQ does not modify
     * the contents */
    memset(resp, 0xFF, sizeof(struct ihc_sbi_msg));

    seL4_HssIhcCall(SBI_EXT_IHC_RX, IHC_CONTEXT_A, config->ihc_buf_pa);

    switch (resp->irq_type) {
    case IHC_MP_IRQ:
        ZF_LOGI("IHC_MP_IRQ: [0x%x 0x%x]", resp->ihc_msg.msg[0],
                resp->ihc_msg.msg[1]);

        vring_idx = resp->ihc_msg.msg[0];
        env_isr((uint32_t)(vring_idx >> 16));
        res = IHC_CALL_MP;
        break;
    case IHC_ACK_IRQ:
        ZF_LOGI("IHC_ACK_IRQ");
        res = IHC_CALL_ACK;
        break;
    default:
        ZF_LOGI("IRQ N/A [0x%x]", resp->irq_type);
    }

    return res;
}

int platform_wait_ihc(uint32_t *ihc_type)
{
    seL4_Word badge = 0;
    int err = -1;
    uint32_t ihc = 0;

    if (ihc_type) {
        *ihc_type = IHC_CALL_INVALID;
    }

    seL4_Wait(sel4_config->ihc_ntf, &badge);

    ihc = platform_ihc_get_next(sel4_config);

    if (ihc_type) {
        *ihc_type = ihc;
    }

    /* Ack the handler so interrupts can come in */
    err = seL4_IRQHandler_Ack(sel4_config->ihc_irq);
    if (err) {
        ZF_LOGE("seL4_IRQHandler_Ack failed: %d", err);
        return RL_NOT_READY;
    }

    return RL_SUCCESS;
}
