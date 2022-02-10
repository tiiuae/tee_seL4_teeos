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
#include <teeos/gen_config.h>
#include <tommath.h>
#include "sys_sel4.h"

#include <utils/zf_log.h>

struct bignum  {
   int used;
   int alloc;
   mp_sign sign;
   mp_digit *dp;
};


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
	_zf_log_write(ZF_LOG_INFO, _ZF_LOG_TAG, str);
}

void sys_return_cleanup(void)
{

	while (true)
		;
}

struct bignum *crypto_bignum_allocate(size_t size_bits)
{
	int err;
	struct bignum *A;
	A = malloc(sizeof(struct bignum));
	if (!A)
		return NULL;

	err = mp_init((void*)A);
	if (err)
	{
		printf("mp_init failed %d\n", err);
		free(A);
		return NULL;
	}
	err = mp_init_size((void*)A, size_bits/sizeof(uint64_t));
	if (err)
	{
		printf("mp_init_size failed %d\n", err);
		free(A);
		return NULL;
	}
	return A;

}
TEE_Result crypto_bignum_bin2bn(const uint8_t *from, size_t fromsize,
				struct bignum *to)
{
	int err;
	if (to == NULL)
	{
		err = mp_init((void*)to);
		if (err)
		{
			printf("mp_init failed %d\n", err);
			return err;
		}
	}
	err = mp_from_ubin((void*)to, from, fromsize);

	return err;
}
void crypto_bignum_bn2bin(const struct bignum *from, uint8_t *to)
{
	int err;

	size_t written;
	err = mp_to_ubin((const void*)from, to, SIZE_MAX, &written);
	if (err)
		printf("%s failed : %d written = %lu\n",__func__, err,  written);
}

size_t crypto_bignum_num_bytes(struct bignum *a)
{
	return mp_ubin_size((void*)a);
}
size_t crypto_bignum_num_bits(struct bignum *a)
{
	 return (8 * mp_ubin_size((void*)a));
}

void crypto_bignum_copy(struct bignum *to, const struct bignum *from)
{
	int err;
	if (to == NULL)
	{
		err = mp_init_copy((void*)from, (void*)to);
	}
	else
	{
		err = mp_copy((void*)from, (void*)to);
	}
	if (err)
		printf("bignum copy failed %d\n", err);
}
void crypto_bignum_free(struct bignum *a)
{
	mp_clear((void*)a);
	free(a);
}
void crypto_bignum_clear(struct bignum *a)
{
	mp_zero((void*)a);
}

TEE_Result tee_time_get_sys_time(TEE_Time *time)
{

	uint64_t n;
	printf("%s %d\n", __func__, __LINE__);

    asm volatile(
        "rdtime %0"
        : "=r"(n));

	/*uint64_t timeinms = (CONFIG_HW_TIMER_FREQ / 1000UL) * n;
	uint32_t seconds = (uint32_t)(timeinms/1000);*/

	uint64_t timeinms = n/(CONFIG_HW_TIMER_FREQ / 1000UL);
	uint32_t seconds = (uint32_t)(n/CONFIG_HW_TIMER_FREQ);
	time->millis = timeinms % 1000;
	time->seconds = seconds;
	return 0;
}
