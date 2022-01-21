// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Linaro Limited
 * Copyright (c) 2020, Arm Limited
 * Copyright (c) 2022, Unikie
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <trace.h>

#include <kernel/tee_common_otp.h>
#include <kernel/huk_subkey.h>
#include <crypto/crypto.h>

#include <sel4runtime.h>
#include <util.h>
#include <sys_ctl_service.h>

#include "sys_sel4.h"

int trace_level = TRACE_LEVEL;
const char trace_ext_prefix[]  = "SEL4";

void __panic(const char *file __maybe_unused, const int line __maybe_unused,
	     const char *func __maybe_unused)
{
	if (!file && !func)
		EMSG_RAW("Panic");
	else
		EMSG_RAW("Panic at %s:%d %s%s%s",
			 file ? file : "?", file ? line : 0,
			 func ? "<" : "", func ? func : "", func ? ">" : "");


	while (true) {
		seL4_Yield();
	}

}

void __do_panic(const char *file __maybe_unused,
		const int line __maybe_unused,
		const char *func __maybe_unused,
		const char *msg __maybe_unused)
{

	/* TODO: notify other cores */

	/* trace: Panic ['panic-string-message' ]at FILE:LINE [<FUNCTION>]" */
	if (!file && !func && !msg)
		EMSG_RAW("Panic");
	else
		EMSG_RAW("Panic %s%s%sat %s:%d %s%s%s",
			 msg ? "'" : "", msg ? msg : "", msg ? "' " : "",
			 file ? file : "?", file ? line : 0,
			 func ? "<" : "", func ? func : "", func ? ">" : "");

	/* abort current execution */
	while (1) {
		seL4_Yield();
	}
}

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	int res = -1;
	uint8_t uid[POLARFIRE_UID_SIZE];
	uint8_t response[32];
	/* Use serial number as a challenge */
	res = get_serial_number(uid);
	if (res)
		return TEE_ERROR_GENERIC;

	res = puf_emulation_service(uid, PUF_UNIQUE_KEY_INDEX, response);
	if (res)
		return TEE_ERROR_GENERIC;

	memcpy(&hwkey->data[0], response, sizeof(hwkey->data));
	return TEE_SUCCESS;
}

int tee_otp_get_die_id(uint8_t *buffer, size_t len)
{
	size_t max_size_uid = POLARFIRE_UID_SIZE;
	int res = -1;

	uint8_t uid[POLARFIRE_UID_SIZE];

	if(!buffer)
		goto err;

	res = get_serial_number(uid);
	if (res)
		goto err;

	memcpy(buffer, &uid, MIN(max_size_uid, len));
	return 0;

err:
	EMSG("Error while getting die ID");
	return -1;
}

int trace_ext_get_thread_id(void)
{
	//FIXME
	return 1;
}

void trace_ext_puts(const char *str)
{
	printf("%s\n", str);
}

void sys_return_cleanup(void)
{
	// _ldelf_return(0);
	/*NOTREACHED*/
	while (true)
		;
}

void crypto_bignum_free(struct bignum *s)
{
	free(s);
}
struct bignum *crypto_bignum_allocate(size_t size_bits)
{
	//FIXME real size calculation
	struct bignum *bn = malloc(size_bits/8);

	if (!bn)
		return NULL;

	return bn;
}

void crypto_bignum_clear(struct bignum *s)
{
	//FIXME
	s = s;
}


TEE_Result tee_time_get_sys_time(TEE_Time *time)
{
	// FIXME
	time->millis = 100;
	time->seconds = 200;
	return 0;
}


TEE_Result sys_map_zi(size_t num_bytes, uint32_t flags, vaddr_t *va,
		      size_t pad_begin, size_t pad_end)
{
	printf("%s\n", __func__);
	return 0;
	//return _ldelf_map_zi(va, num_bytes, pad_begin, pad_end, flags);
}

TEE_Result sys_unmap(vaddr_t va, size_t num_bytes)
{
	printf("%s\n", __func__);
	return 0;
	//return _ldelf_unmap(va, num_bytes);
}

TEE_Result sys_open_ta_bin(const TEE_UUID *uuid, uint32_t *handle)
{
	printf("%s\n", __func__);
	return 0;
	//return _ldelf_open_bin(uuid, sizeof(TEE_UUID), handle);
}

TEE_Result sys_close_ta_bin(uint32_t handle)
{
	printf("%s\n", __func__);
	return 0;
	//return _ldelf_close_bin(handle);
}

TEE_Result sys_map_ta_bin(vaddr_t *va, size_t num_bytes, uint32_t flags,
			  uint32_t handle, size_t offs, size_t pad_begin,
			  size_t pad_end)
{
	printf("%s\n", __func__);
	return 0;
	/*return _ldelf_map_bin(va, num_bytes, handle, offs,
			     pad_begin, pad_end, flags);*/
}


TEE_Result sys_copy_from_ta_bin(void *dst, size_t num_bytes, uint32_t handle,
				size_t offs)
{
	printf("%s\n", __func__);
	return 0;
	//return _ldelf_cp_from_bin(dst, offs, num_bytes, handle);
}

TEE_Result sys_set_prot(vaddr_t va, size_t num_bytes, uint32_t flags)
{
	printf("%s\n", __func__);
	return 0;
	//return _ldelf_set_prot(va, num_bytes, flags);
}

TEE_Result sys_remap(vaddr_t old_va, vaddr_t *new_va, size_t num_bytes,
		     size_t pad_begin, size_t pad_end)
{
	printf("%s\n", __func__);
	return 0;
	//return _ldelf_remap(old_va, new_va, num_bytes, pad_begin, pad_end);
}

TEE_Result sys_gen_random_num(void *buf, size_t blen)
{
	printf("%s\n", __func__);
	return 0;
	//return _ldelf_gen_rnd_num(buf, blen);
}
