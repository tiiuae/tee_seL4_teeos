/*
 * Copyright 2022, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _SEL4_CRASHLOG_H_
#define _SEL4_CRASHLOG_H_

#include <stdint.h>
#include "spinlock.h"
#include "sel4_circ.h"

#define CRASHLOG_PAYLOAD_PAGES  1

/* memory structure in the beginning of crashlog area */
struct crashlog_hdr {
    struct circ_buf_hdr circ_hdr;
    sync_spinlock_t writer_lock;
    sync_spinlock_t reader_lock;
};

struct crashlog_ctx {
    struct crashlog_hdr *hdr;
    char *buf;
};

void sel4_crashlog_init_once(void *crashlog);

void sel4_crashlog_setup_cb(struct crashlog_ctx *ctx, void *crashlog);

#endif /* _SEL4_CRASHLOG_H_ */