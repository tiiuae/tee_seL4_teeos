/*
 * Copyright (c) 2014, Mentor Graphics Corporation
 * Copyright (c) 2015 Xilinx, Inc.
 * Copyright (c) 2016 Freescale Semiconductor, Inc.
 * Copyright 2016-2019 NXP
 * Copyright 2021 Unikie
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**************************************************************************
 * FILE NAME
 *
 *       rpmsg_env_sel4.c
 *
 *
 * DESCRIPTION
 *
 *       This file is seL4 Implementation of env layer for OpenAMP.
 *
 *
 **************************************************************************/

#include "rpmsg_env.h"
#include "rpmsg_platform.h"
#include "virtqueue.h"
#include "rpmsg_compiler.h"
#include "rpmsg_lite.h"

#include <stdlib.h>
#include <string.h>

#include <sel4runtime.h>
#include "spinlock_yield.h"

#include "sel4_circ.h"

/* Local log level */
#define ZF_LOG_LEVEL ZF_LOG_ERROR
#include <utils/util.h>
#include <utils/zf_log.h>

#define UNUSED_VAR(x) (void)(x)

static int32_t env_init_counter   = 0;

#define RL_ENV_MAX_MUTEX_COUNT (10)

static uint8_t mutex_count = 0;
static sync_spinlock_t locks[RL_ENV_MAX_MUTEX_COUNT];

/* Max supported ISR counts */
#define ISR_COUNT (32U)
/*!
 * Structure to keep track of registered ISR's.
 */
struct isr_info
{
    void *data;
};
static struct isr_info isr_table[ISR_COUNT];

/* Circular buffer config & control */
struct queue_ctx {
    struct tee_comm_ch circ_config;
    struct tee_comm_ctrl ctrl_reserved;  /* used by circ_config */
    sync_spinlock_t writer_lock;
    sync_spinlock_t reader_lock;
    int32_t element_size;
    int32_t element_count;
};

/*!
 * env_init
 *
 * Initializes OS/BM environment.
 *
 */
int32_t env_init(void)
{
    if (env_init_counter)
        return 0;

    env_init_counter = 1;

    (void)memset(isr_table, 0, sizeof(isr_table));
    return platform_init();
}

/*!
 * env_deinit
 *
 * Uninitializes OS/BM environment.
 *
 * @returns - execution status
 */
int32_t env_deinit(void)
{
    if (!env_init_counter)
        return 0;

    env_init_counter = 0;

    platform_deinit();

    return 0;
}

/*!
 * env_allocate_memory - implementation
 *
 * @param size
 */
void *env_allocate_memory(uint32_t size)
{
    return (malloc(size));
}

/*!
 * env_free_memory - implementation
 *
 * @param ptr
 */
void env_free_memory(void *ptr)
{
    if (ptr != ((void *)0))
    {
        free(ptr);
    }
}

/*!
 *
 * env_memset - implementation
 *
 * @param ptr
 * @param value
 * @param size
 */
void env_memset(void *ptr, int32_t value, uint32_t size)
{
    (void)memset(ptr, value, size);
}

/*!
 *
 * env_memcpy - implementation
 *
 * @param dst
 * @param src
 * @param len
 */
void env_memcpy(void *dst, void const *src, uint32_t len)
{
    (void)memcpy(dst, src, len);
}

/*!
 *
 * env_strcmp - implementation
 *
 * @param dst
 * @param src
 */

int32_t env_strcmp(const char *dst, const char *src)
{
    return (strcmp(dst, src));
}

/*!
 *
 * env_strncpy - implementation
 *
 * @param dest
 * @param src
 * @param len
 */
void env_strncpy(char *dest, const char *src, uint32_t len)
{
    (void)strncpy(dest, src, len);
}

/*!
 *
 * env_strncmp - implementation
 *
 * @param dest
 * @param src
 * @param len
 */
int32_t env_strncmp(char *dest, const char *src, uint32_t len)
{
    return (strncmp(dest, src, len));
}

/*!
 *
 * env_mb - implementation
 *
 */
void env_mb(void)
{
    MEM_BARRIER();
}

/*!
 * env_rmb - implementation
 */
void env_rmb(void)
{
    MEM_BARRIER();
}

/*!
 * env_wmb - implementation
 */
void env_wmb(void)
{
    MEM_BARRIER();
}


/*!
 * env_map_vatopa - implementation
 *
 * @param address
 */
uint32_t env_map_vatopa(void *address)
{
    return platform_vatopa(address);
}

/*!
 * env_map_patova - implementation
 *
 * @param address
 */
void *env_map_patova(uint32_t address)
{
    return platform_patova(address);
}

/*!
 * env_create_mutex
 *
 * Creates a mutex with the given initial count.
 *
 */
int32_t env_create_mutex(void **lock, int32_t count)
{
    if (mutex_count >= RL_ENV_MAX_MUTEX_COUNT)
    {
        ZF_LOGE("max mutex count");
        return RL_ERR_PARAM;
    }

    sync_spinlock_t *next = &locks[mutex_count++];

    *lock = next;

    sync_spinlock_init(next);

    return 0;
}

/*!
 * env_delete_mutex
 *
 * Deletes the given lock
 *
 */
void env_delete_mutex(void *lock)
{
    // TODO: implement queue for locks
}

/*!
 * env_lock_mutex
 *
 * Tries to acquire the lock, if lock is not available then call to
 * this function will suspend.
 */
void env_lock_mutex(void *lock)
{
    sync_spinlock_lock_yield(lock);
}

/*!
 * env_unlock_mutex
 *
 * Releases the given lock.
 */
void env_unlock_mutex(void *lock)
{
    sync_spinlock_unlock(lock);
}

/*!
 * env_sleep_msec
 *
 * Suspends the calling thread for given time , in msecs.
 */
void env_sleep_msec(uint32_t num_msec)
{
    platform_time_delay(num_msec);
}

/*!
 * env_register_isr
 *
 * Registers interrupt handler data for the given interrupt vector.
 *
 * @param vector_id - virtual interrupt vector number
 * @param data      - interrupt handler data (virtqueue)
 */
void env_register_isr(uint32_t vector_id, void *data)
{
    RL_ASSERT(vector_id < ISR_COUNT);
    if (vector_id < ISR_COUNT)
    {
        isr_table[vector_id].data = data;
    }
}

/*!
 * env_unregister_isr
 *
 * Unregisters interrupt handler data for the given interrupt vector.
 *
 * @param vector_id - virtual interrupt vector number
 */
void env_unregister_isr(uint32_t vector_id)
{
    RL_ASSERT(vector_id < ISR_COUNT);
    if (vector_id < ISR_COUNT)
    {
        isr_table[vector_id].data = ((void *)0);
    }
}

/*!
 * env_enable_interrupt
 *
 * Enables the given interrupt
 *
 * @param vector_id   - virtual interrupt vector number
 */

void env_enable_interrupt(uint32_t vector_id)
{
    (void)platform_interrupt_enable(vector_id);
}

/*!
 * env_disable_interrupt
 *
 * Disables the given interrupt
 *
 * @param vector_id   - virtual interrupt vector number
 */

void env_disable_interrupt(uint32_t vector_id)
{
    (void)platform_interrupt_disable(vector_id);
}

/*========================================================= */
/* Util data / functions  */

void env_isr(uint32_t vector)
{
    struct isr_info *info;

    ZF_LOGF_IF(vector >= ISR_COUNT, "ERROR vector %d", vector);
    RL_ASSERT(vector < ISR_COUNT);
    if (vector < ISR_COUNT)
    {
        info = &isr_table[vector];

        virtqueue_notification((struct virtqueue *)info->data);
    }
}

/*
 * env_create_queue
 *
 * Creates a message queue.
 *
 * @param queue -  pointer to created queue
 * @param length -  maximum number of elements in the queue
 * @param element_size - queue element size in bytes
 *
 * @return - status of function execution
 */
int32_t env_create_queue(void **queue, int32_t length, int32_t element_size)
{
    int32_t queue_bytes = length * element_size;
    int32_t ctx_buf_len = 0;
    void *ctx_buf = NULL;
    struct queue_ctx *ctx = NULL;

    /* circular buffer requires power of 2 length */
    if (!IS_POWER_OF_2(queue_bytes)) {
        queue_bytes = NEXT_POWER_OF_2(queue_bytes);
    }

    /* Allocate mem for both CIRC buffer and ctx struct 
     *     { 
     *         [CIRC buffer / queue],
     *         struct queue_ctx
     *     }
     */
    ctx_buf_len = queue_bytes + sizeof(struct queue_ctx);

    ctx_buf = env_allocate_memory(ctx_buf_len);
    if (!ctx_buf) {
        ZF_LOGE("out of memory");
        return RL_ERR_NO_MEM;
    }

    memset(ctx_buf, 0x0, ctx_buf_len);

    /* Locate ctx area after CIRC buffer. Queue length is power of 2 which
     * also aligns the following struct */
    ctx = ctx_buf + queue_bytes;

    /* ctx reserves space for ctrl struct */
    ctx->circ_config.ctrl = &ctx->ctrl_reserved;

    /* link actual CIRC buffer to ctrl*/
    ctx->circ_config.buf = ctx_buf;
    ctx->circ_config.buf_len = queue_bytes;

    ctx->element_size = element_size;

    sync_spinlock_init(&ctx->writer_lock);
    sync_spinlock_init(&ctx->reader_lock);

    *queue = ctx;

    return 0;
}

/*!
 * env_delete_queue
 *
 * Deletes the message queue.
 *
 * @param queue - queue to delete
 */

void env_delete_queue(void *queue)
{
    env_free_memory(queue);
}

/*!
 * env_put_queue
 *
 * Put an element in a queue.
 *
 * @param queue - queue to put element in
 * @param msg - pointer to the message to be put into the queue
 * @param timeout_ms - timeout in ms
 *
 * @return - status of function execution
 */

int32_t env_put_queue(void *queue, void *msg, uint32_t timeout_ms)
{
    struct queue_ctx *ctx = (struct queue_ctx *)queue;
    int ret = -1;

    if (sel4_write_to_circ(&ctx->circ_config,
                       ctx->element_size,
                       (char *)msg,
                       &ctx->writer_lock)) {
        ZF_LOGE("write_circ: ENOSPC l[%d] ec[%d]", ctx->element_size, ctx->element_count);
        return 0; /* FAILURE */
    }

    ctx->element_count++;

    return 1; /* SUCCESS */
}

/*!
 * env_get_queue
 *
 * Get an element out of a queue.
 *
 * @param queue - queue to get element from
 * @param msg - pointer to a memory to save the message
 * @param timeout_ms - timeout in ms
 *
 * @return - status of function execution
 */

int32_t env_get_queue(void *queue, void *msg, uint32_t timeout_ms)
{
    struct queue_ctx *ctx = (struct queue_ctx *)queue;
    int32_t read_len = 0;

    UNUSED_VAR(timeout_ms);

    if (sel4_read_from_circ(&ctx->circ_config,
                            ctx->element_size,
                            (char*)msg,
                            &read_len,
                            &ctx->reader_lock)) {
        ZF_LOGE("read_circ: ENODATA l[%d] ec[%d]", read_len, ctx->element_count);
        return 0; /* FAILURE */
    }

    ctx->element_count--;

    return 1; /* SUCCESS */
}

/*!
 * env_get_current_queue_size
 *
 * Get current queue size.
 *
 * @param queue - queue pointer
 *
 * @return - Number of queued items in the queue
 */

int32_t env_get_current_queue_size(void *queue)
{
    struct queue_ctx *ctx = (struct queue_ctx *)queue;

    return ctx->element_count;
}
