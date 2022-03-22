/*
 * Copyright 2022, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _SEL4_CRASHLOG_H_
#define _SEL4_CRASHLOG_H_

#include <stdint.h>
#include <string.h>
#include <platsupport/sync/spinlock.h>
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

/* Caller must allocate memory for context and preserve it */
static struct crashlog_ctx *zf_crashlog_ctx;

#ifndef ZF_LOG_EOL
	#define ZF_LOG_EOL "\n"
#endif

#ifndef ZF_LOG_FATAL
    #define ZF_LOG_FATAL   0xFFFF
#endif

/* originated from projects/util_libs/libutils/src/zf_log.c: output_callback() */
static inline void zf_crashlog_cb(zf_log_output_ctx *const ctx)
{
    int ret = 0;

    /* combine info for circ-functions */
    struct circ_ctx circ = {
        .hdr = &zf_crashlog_ctx->hdr->circ_hdr,
        .buf = zf_crashlog_ctx->buf,
    };

    char tmp_buf[16]; /* short buffer to empty CIRC if it gets full */
    int32_t read_len = 0;

    strcpy(ctx->p, ZF_LOG_EOL);
    fputs(ctx->buf, stderr);

    ret = sel4_write_to_circ(&circ,
                             strlen(ctx->buf),
                             ctx->buf,
                             &zf_crashlog_ctx->hdr->writer_lock);

    /* crashlog full, erase "some amount" of crashlog by reading it out */
    if (ret == -ENOSPC) {
        for (int i = 0; i < 30; i++) {
            sel4_read_from_circ(&circ,
                                sizeof(tmp_buf),
                                tmp_buf,
                                &read_len,
                                &zf_crashlog_ctx->hdr->reader_lock);
        }

        /* second try, best effort */
        sel4_write_to_circ(&circ,
                           strlen(ctx->buf),
                           ctx->buf,
                           &zf_crashlog_ctx->hdr->writer_lock);
    }

    if (ZF_LOG_FATAL == ctx->lvl) {
        fflush(stderr);
        abort();
    }
}

/* Caller must allocate memory for context and preserve it */
static inline void sel4_crashlog_setup_cb(struct crashlog_ctx *ctx, void *crashlog)
{
    zf_crashlog_ctx = ctx;

    ctx->hdr = (struct crashlog_hdr *)crashlog;
    ctx->hdr->circ_hdr.buf_len = PAGE_SIZE_4K * CRASHLOG_PAYLOAD_PAGES; /* must be power of 2 */

    ctx->buf = (char *)crashlog + sizeof(struct crashlog_hdr);

    /* TODO: each client inits same spinlocks after each other.
     * For now this is not a problem...
     */
    sync_spinlock_init(&ctx->hdr->writer_lock);
    sync_spinlock_init(&ctx->hdr->reader_lock);

    zf_log_set_output_callback(&zf_crashlog_cb);
}

#endif /* _SEL4_CRASHLOG_H_ */