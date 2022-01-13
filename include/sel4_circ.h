/*
 * Copyright 2021, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <string.h>
#include <errno.h>
#include <sel4runtime.h>
#include <platsupport/sync/spinlock.h>
#include <utils/arith.h>
#include <linux/circ_buf.h>

#include <teeos_common.h>

/* Linux code compatibility defines. Used in CIRC functions to keep
 * the source code same as in Linux driver.
 */
#define spin_lock(lock)                 sync_spinlock_lock((sync_spinlock_t *)lock)
#define spin_unlock(lock)               sync_spinlock_unlock((sync_spinlock_t *)lock)

#define READ_ONCE(source)               __atomic_load_n(&source, __ATOMIC_RELAXED)
#define smp_store_release(dest, val)    __atomic_store_n(dest, val, __ATOMIC_RELEASE)
#define smp_load_acquire(source)        __atomic_load_n(source, __ATOMIC_ACQUIRE)

#define min(a,b)    MIN(a,b)

/*
 * Design copied from producer example: linux/Documentation/core-api/circular-buffers.rst
 */
static inline int sel4_write_to_circ(struct tee_comm_ch *circ, int32_t data_len,
                       const char *data_in, void *writer_lock)
{
    int ret = -ENOSPC;
    int32_t head = 0;
    int32_t tail = 0;
    int32_t buf_end = 0;
    int32_t write_ph1 = 0;
    int32_t wrap = 0;

    spin_lock(writer_lock);

    head = circ->ctrl->head;

    /* The spin_unlock() and next spin_lock() provide needed ordering. */
    tail = READ_ONCE(circ->ctrl->tail);

    /* Shrink consecutive writes to the buffer end */
    buf_end = CIRC_SPACE_TO_END(head, tail, circ->buf_len);
    write_ph1 = min(buf_end, data_len);

    /* Remaining data if wrap needed, otherwise zero */
    wrap = data_len - write_ph1;

    if (CIRC_SPACE(head, tail, circ->buf_len) >= data_len) {
        memcpy(&circ->buf[head], data_in, write_ph1);

        /* Head will be automatically rolled back to the beginning of the buffer */
        head = (head + write_ph1) & (circ->buf_len - 1);

        if (wrap) {
            memcpy(&circ->buf[head], &data_in[write_ph1], wrap);
            head = (head + wrap) & (circ->buf_len - 1);
        }

        /* update the head after buffer write */
        smp_store_release(&circ->ctrl->head, head);

        /* TODO: wakeup reader */
        ret = 0;
    }

    spin_unlock(writer_lock);

    return ret;
}

/*
 * Design copied from consumer example: linux/Documentation/core-api/circular-buffers.rst
 */
static inline int sel4_read_from_circ(struct tee_comm_ch *circ, int32_t out_len,
                        char *out_buf, int32_t *read_len, void *reader_lock)
{
    int ret = -ENODATA;
    int32_t head = 0;
    int32_t tail = 0;
    int32_t available = 0;
    int32_t buf_end = 0;
    int32_t read_ph1 = 0;
    int32_t wrap = 0;

    spin_lock(reader_lock);

    /* Read index before reading contents at that index. */
    head = smp_load_acquire(&circ->ctrl->head);
    tail = circ->ctrl->tail;

    /* Shrink read length to output buffer size */
    available = min(out_len, CIRC_CNT(head, tail, circ->buf_len));

    /* Shrink consecutive reads to the buffer end */
    buf_end = CIRC_CNT_TO_END(head, tail, circ->buf_len);
    read_ph1 = min(available, buf_end);

    /* Remaining data if wrap needed, otherwise zero */
    wrap = available - read_ph1;

    *read_len = 0;

    if (available >= 1) {
        memcpy(out_buf, &circ->buf[tail], read_ph1);
        tail = (tail + read_ph1) & (circ->buf_len - 1);

        *read_len = read_ph1;

        if (wrap) {
            memcpy(&out_buf[read_ph1], &circ->buf[tail], wrap);
            tail = (tail + wrap) & (circ->buf_len - 1);
            *read_len += wrap;
        }

        /* Finish reading descriptor before incrementing tail. */
        smp_store_release(&circ->ctrl->tail, tail);

        ret = 0;
    }

    spin_unlock(reader_lock);

    return ret;
}
