// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2015-2021 Linaro Limited
 * Copyright (c) 2020, Arm Limited.
 * Copyright (c) 2022, Unikie.
 * 
 * Ripoff from original user_ta.c
 */


#include <assert.h>
#include <compiler.h>
#include <crypto/crypto.h>
#include <ctype.h>
#include <initcall.h>
#include <keep.h>
#include <kernel/linker.h>
#include <kernel/panic.h>
#include <kernel/tee_misc.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/ts_store.h>
#include <kernel/user_access.h>
#include <kernel/user_ta.h>
#include <optee_rpc_cmd.h>
#include <printk.h>
#include <signed_hdr.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <ta_pub_key.h>
#include <tee/tee_cryp_utl.h>
#include <tee/tee_obj.h>
#include <tee/tee_svc_cryp.h>
#include <tee/tee_svc.h>
#include <tee/tee_svc_storage.h>
#include <tee/uuid.h>
#include <trace.h>
#include <types_ext.h>
#include <utee_defines.h>
#include <util.h>
#include <kernel/mutex.h>


struct tee_ta_ctx_head tee_ctxes = TAILQ_HEAD_INITIALIZER(tee_ctxes);
TEE_Result tee_ta_init_user_ta_session(const TEE_UUID *uuid,
				       struct tee_ta_session *s)
{
	struct user_ta_ctx *utc = NULL;
	utc = calloc(1, sizeof(struct user_ta_ctx));
	if (!utc)
		return TEE_ERROR_OUT_OF_MEMORY;

	utc->uctx.is_initializing = true;
	TAILQ_INIT(&utc->open_sessions);
	TAILQ_INIT(&utc->cryp_states);
	TAILQ_INIT(&utc->objects);
	TAILQ_INIT(&utc->storage_enums);
	
	utc->ta_ctx.ref_count = 1;

	utc->uctx.ts_ctx = &utc->ta_ctx.ts_ctx;

	/*
	 * Set context TA operation structure. It is required by generic
	 * implementation to identify userland TA versus pseudo TA contexts.
	 */
	

	utc->ta_ctx.ts_ctx.uuid = *uuid;
	s->ts_sess.ctx = &utc->ta_ctx.ts_ctx;
	/*
	 * Another thread trying to load this same TA may need to wait
	 * until this context is fully initialized. This is needed to
	 * handle single instance TAs.
	 */
	TAILQ_INSERT_TAIL(&tee_ctxes, &utc->ta_ctx, link);
	ts_push_current_session(&s->ts_sess);

	utc->uctx.is_initializing = false;

	return 0;
}
