/*
 * Copyright 2022, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <utils/page.h>
#include "spinlock.h"
#include "sel4_circ.h"
#include <utils/zf_log.h>
#include "sel4_crashlog.h"

#ifndef ZF_LOG_EOL
	#define ZF_LOG_EOL "\n"
#endif

#ifndef ZF_LOG_FATAL
    #define ZF_LOG_FATAL   0xFFFF
#endif

static const char highlight_error[] = "\033[1;31m";
static const char highlight_normal[] = "\033[0m";

/* Caller must allocate memory for context and preserve it */
static struct crashlog_ctx *zf_crashlog_ctx;

/* originated from projects/util_libs/libutils/src/zf_log.c: output_callback() */
static void zf_crashlog_cb(zf_log_output_ctx *const ctx)
{
    int ret = 0;

    /* combine info for circ-functions */
    struct circ_ctx circ = {
        .hdr = &zf_crashlog_ctx->hdr->circ_hdr,
        .buf = zf_crashlog_ctx->buf,
    };

    char tmp_buf[16]; /* short buffer to empty CIRC if it gets full */
    int32_t read_len = 0;

    if (!ctx)
        return;

    strcpy(ctx->p, ZF_LOG_EOL);

#ifdef TRACE_ERROR_HIGHLIGHT
    if (ctx->lvl == ZF_LOG_ERROR) {
        fputs(highlight_error, stderr);
    }
#endif /* TRACE_ERROR_HIGHLIGHT */

    fputs(ctx->buf, stderr);

#ifdef TRACE_ERROR_HIGHLIGHT
    if (ctx->lvl == ZF_LOG_ERROR) {
        fputs(highlight_normal, stderr);
    }
#endif /* TRACE_ERROR_HIGHLIGHT */

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

/*
 * Caller must allocate memory for context and preserve it.
 *
 * Each application / camkes component should call this function.
 */
void sel4_crashlog_setup_cb(struct crashlog_ctx *ctx, void *crashlog)
{
    if (!ctx || !crashlog)
        return;

    zf_crashlog_ctx = ctx;

    ctx->hdr = (struct crashlog_hdr *)crashlog;

    ctx->buf = (char *)crashlog + sizeof(struct crashlog_hdr);

    zf_log_set_output_callback(&zf_crashlog_cb);
}

/* Only first client should call this function to initialize header */
void sel4_crashlog_init_once(void *crashlog)
{
    struct crashlog_hdr *hdr = (struct crashlog_hdr *)crashlog;

    if (!crashlog)
        return;

    memset(&hdr->circ_hdr, 0x0, sizeof(struct circ_buf_hdr));

    hdr->circ_hdr.buf_len = PAGE_SIZE_4K * CRASHLOG_PAYLOAD_PAGES; /* must be power of 2 */

    sync_spinlock_init(&hdr->writer_lock);
    sync_spinlock_init(&hdr->reader_lock);
}