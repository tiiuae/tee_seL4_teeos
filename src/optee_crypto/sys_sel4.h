/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, Linaro Limited
 * Copyright (c) 2020, Arm Limited
 * Copyright (c) 2022, Unikie
 */

#ifndef SYS_SEL4_H
#define SYS_SEL4_H

#include <compiler.h>
#include <stddef.h>
#include <tee_api_types.h>
#include <trace.h>
#include <types_ext.h>

struct utee_params;

#define panic()    ZF_LOGF("panic %d  %s", __LINE__, __func__)

#define POLARFIRE_UID_SIZE 16
#define PUF_UNIQUE_KEY_INDEX 1


/* A small page is the smallest unit of memory that can be mapped */
#define SMALL_PAGE_SHIFT	seL4_PageBits
#define SMALL_PAGE_MASK		0x00000fff
#define SMALL_PAGE_SIZE		0x00001000

void __noreturn __panic(const char *file, const int line, const char *func);
void __noreturn sys_return_cleanup(void);

int init_fortuna_rng(void);
int sys_reseed_fortuna_rng(void);

#define err(res, ...) \
	do { \
		trace_printf_helper(TRACE_ERROR, true, __VA_ARGS__); \
	} while (0)

void init_sel4_mempool(void);

TEE_Result entry_open_session_sel4(unsigned long session_id,
			struct utee_params *up);

TEE_Result entry_invoke_command_sel4(unsigned long session_id,
			TEE_Param params[TEE_NUM_PARAMS], uint32_t param_types, unsigned long cmd_id);

TEE_Result entry_close_session_sel4(unsigned long session_id);

#endif /*SYS_SEL4_H*/
