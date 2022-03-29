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

TEE_Result sys_map_zi(size_t num_bytes, uint32_t flags, vaddr_t *va,
		      size_t pad_begin, size_t pad_end);
TEE_Result sys_unmap(vaddr_t va, size_t num_bytes);
TEE_Result sys_open_ta_bin(const TEE_UUID *uuid, uint32_t *handle);
TEE_Result sys_close_ta_bin(uint32_t handle);
TEE_Result sys_map_ta_bin(vaddr_t *va, size_t num_bytes, uint32_t flags,
			  uint32_t handle, size_t offs, size_t pad_begin,
			  size_t pad_end);
TEE_Result sys_copy_from_ta_bin(void *dst, size_t num_bytes, uint32_t handle,
				size_t offs);
TEE_Result sys_set_prot(vaddr_t va, size_t num_bytes, uint32_t flags);
TEE_Result sys_remap(vaddr_t old_va, vaddr_t *new_va, size_t num_bytes,
		     size_t pad_begin, size_t pad_end);
TEE_Result sys_gen_random_num(void *buf, size_t blen);

void init_sel4_mempool(void);

TEE_Result entry_open_session_sel4(unsigned long session_id,
			struct utee_params *up);

TEE_Result entry_invoke_command2(unsigned long session_id,
			struct utee_params *up, unsigned long cmd_id);

TEE_Result entry_invoke_command_sel4(unsigned long session_id,
			TEE_Param params[TEE_NUM_PARAMS], uint32_t param_types, unsigned long cmd_id);

TEE_Result entry_close_session_sel4(unsigned long session_id);

#endif /*SYS_SEL4_H*/
