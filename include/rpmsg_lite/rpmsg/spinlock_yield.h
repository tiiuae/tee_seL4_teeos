/*
 * Copyright 2021 Unike
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <stdbool.h>
#include <sel4runtime.h>
#include "spinlock.h"

/* sync_spinlock_lock() + seL4_Yield() */
static inline int sync_spinlock_lock_yield(sync_spinlock_t *lock) {
    while (true) {
        int expected = 0;
        if (__atomic_compare_exchange_n(lock, &expected, 1, 1, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
            break;
        }
        seL4_Yield();
    }
    return 0;
}
