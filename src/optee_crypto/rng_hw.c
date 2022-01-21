// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2018, Linaro Limited 
 * Copyright (c) 2022, Unikie
 */

#include <compiler.h>
#include <crypto/crypto.h>
#include <rng_support.h>
#include <tee/tee_cryp_utl.h>
#include <types_ext.h>

#include <sys_ctl_service.h>




TEE_Result crypto_rng_init(const void *data __unused,
				  size_t dlen __unused)
{
	return TEE_SUCCESS;
}

void __weak crypto_rng_add_event(enum crypto_rng_src sid __unused,
				 unsigned int *pnum __unused,
				 const void *data __unused,
				 size_t dlen __unused)
{
}

TEE_Result crypto_rng_read(void *buf, size_t blen)
{
	uint8_t *b = buf;
	size_t n;
	uint8_t tmp_buf[32];
	size_t rng_count;
	size_t extra_bytes;

	if (!b)
		return TEE_ERROR_BAD_PARAMETERS;

	nonce_service(tmp_buf);

	if (blen < 32)
	{
		for (n = 0; n < blen; n++)
		{
			b[n] = tmp_buf[n];
		}
	}
	else
	{
		rng_count = blen / 32u;
		extra_bytes = blen % 32u;

		for( int i = 0; i < rng_count; i++)
		{
			nonce_service(tmp_buf);
			for(n = 0; n < 32u; n++)
			{
				b[(i * 32) + n] =tmp_buf[n];
			}

		}
		/*final bytes */
		nonce_service(tmp_buf);
		for (n = 0; n < extra_bytes; n++)
		{
			b[rng_count * 32 + n] = tmp_buf[n];
		}


	}
	return TEE_SUCCESS;
}

