// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#include <compiler.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <tee_api.h>
#include <tee_ta_api.h>
#include <tee_internal_api_extensions.h>
#include <user_ta_header.h>
#include <utee_syscalls.h>
#include <tee_arith_internal.h>
#include <malloc.h>
#include "tee_api_private.h"
#include <utee_types.h>

struct ta_session {
	uint32_t session_id;
	void *session_ctx;
	TAILQ_ENTRY(ta_session) link;
};


static TAILQ_HEAD(ta_sessions, ta_session) ta_sessions =
		TAILQ_HEAD_INITIALIZER(ta_sessions);

static bool init_done = false;

/* From user_ta_header.c, built within TA */
extern uint8_t ta_heap[];
extern const size_t ta_heap_size;
extern struct ta_head ta_head;

uint32_t ta_param_types;
TEE_Param ta_params[TEE_NUM_PARAMS];
struct __elf_phdr_info __elf_phdr_info;


static TAILQ_HEAD(phdr_info_head, phdr_info) __phdr_info_head =
		TAILQ_HEAD_INITIALIZER(__phdr_info_head);
/*
 * Keep track of how many modules have been initialized so that subsequent
 * dlopen() calls will not run the same initializers again
 */



/* static size_t _num_mod_init; */

static void ta_header_save_params(uint32_t param_types,
				  TEE_Param params[TEE_NUM_PARAMS])
{
	ta_param_types = param_types;

	if (params)
		memcpy(ta_params, params, sizeof(ta_params));
	else
		memset(ta_params, 0, sizeof(ta_params));
}

static struct ta_session *ta_header_get_session(uint32_t session_id)
{
	struct ta_session *itr;

	TAILQ_FOREACH(itr, &ta_sessions, link) {
		if (itr->session_id == session_id)
			return itr;
	}
	return NULL;
}

static TEE_Result ta_header_add_session(uint32_t session_id)
{
	struct ta_session *itr = ta_header_get_session(session_id);
	/* TEE_Result res; */

	if (itr)
		return TEE_SUCCESS;

	if (!init_done) {
		init_done = true;
		int res = TA_CreateEntryPoint();
		if (res)
			return res;
	}

	itr = TEE_Malloc(sizeof(struct ta_session),
			TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!itr)
		return TEE_ERROR_OUT_OF_MEMORY;
	itr->session_id = session_id;
	itr->session_ctx = 0;
	TAILQ_INSERT_TAIL(&ta_sessions, itr, link);

	return TEE_SUCCESS;
}

static void ta_header_remove_session(uint32_t session_id)
{
	struct ta_session *itr;
	bool keep_alive;

	TAILQ_FOREACH(itr, &ta_sessions, link) {
		if (itr->session_id == session_id) {
			TAILQ_REMOVE(&ta_sessions, itr, link);
			TEE_Free(itr);

			 keep_alive =
				(ta_head.flags & TA_FLAG_SINGLE_INSTANCE) &&
				(ta_head.flags & TA_FLAG_INSTANCE_KEEP_ALIVE);
			if (TAILQ_EMPTY(&ta_sessions) && !keep_alive)
				TA_DestroyEntryPoint();

			return;
		}
	}
}

static void to_utee_params(struct utee_params *up, uint32_t param_types,
			   const TEE_Param params[TEE_NUM_PARAMS])
{
	size_t n = 0;

	up->types = param_types;
	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		switch (TEE_PARAM_TYPE_GET(param_types, n)) {
		case TEE_PARAM_TYPE_VALUE_INPUT:
		case TEE_PARAM_TYPE_VALUE_OUTPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
			up->vals[n * 2] = params[n].value.a;
			up->vals[n * 2 + 1] = params[n].value.b;
			break;
		case TEE_PARAM_TYPE_MEMREF_INPUT:
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			up->vals[n * 2] = (uintptr_t)params[n].memref.buffer;
			up->vals[n * 2 + 1] = params[n].memref.size;
			break;
		default:
			up->vals[n * 2] = 0;
			up->vals[n * 2 + 1] = 0;
			break;
		}
	}
}

static void from_utee_params(TEE_Param params[TEE_NUM_PARAMS],
			     uint32_t *param_types,
			     const struct utee_params *up)
{
	size_t n;
	uint32_t types = up->types;

	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		uintptr_t a = up->vals[n * 2];
		uintptr_t b = up->vals[n * 2 + 1];

		switch (TEE_PARAM_TYPE_GET(types, n)) {
		case TEE_PARAM_TYPE_VALUE_INPUT:
		case TEE_PARAM_TYPE_VALUE_OUTPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
			params[n].value.a = a;
			params[n].value.b = b;
			break;
		case TEE_PARAM_TYPE_MEMREF_INPUT:
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			params[n].memref.buffer = (void *)a;
			params[n].memref.size = b;
			break;
		default:
			break;
		}
	}

	if (param_types)
		*param_types = types;
}

TEE_Result entry_open_session_sel4(unsigned long session_id,
			struct utee_params *up)
{
	TEE_Result res;
	struct ta_session *session;
	uint32_t param_types;
	TEE_Param params[TEE_NUM_PARAMS];

	res = ta_header_add_session(session_id);
	if (res != TEE_SUCCESS)
	{
		return res;
	}
	session = ta_header_get_session(session_id);

	if (!session)
	{
		return TEE_ERROR_BAD_STATE;
	}

	from_utee_params(params, &param_types, up);
	ta_header_save_params(param_types, params);

	res = TA_OpenSessionEntryPoint(param_types, params,
				       &session->session_ctx);


	to_utee_params(up, param_types, params);

	if (res != TEE_SUCCESS)
		ta_header_remove_session(session_id);
	return res;
}

TEE_Result entry_close_session_sel4(unsigned long session_id)
{
	struct ta_session *session = ta_header_get_session(session_id);

	if (!session)
		return TEE_ERROR_BAD_STATE;

	TA_CloseSessionEntryPoint(session->session_ctx);

	ta_header_remove_session(session_id);
	return TEE_SUCCESS;
}

TEE_Result entry_invoke_command2(unsigned long session_id,
			struct utee_params *up, unsigned long cmd_id)
{
	TEE_Result res;
	uint32_t param_types;
	TEE_Param params[TEE_NUM_PARAMS];
	struct ta_session *session = ta_header_get_session(session_id);

	if (!session)
		return TEE_ERROR_BAD_STATE;

	from_utee_params(params, &param_types, up);
	ta_header_save_params(param_types, params);

	res = TA_InvokeCommandEntryPoint(session->session_ctx, cmd_id,
					 param_types, params);

	to_utee_params(up, param_types, params);
	return res;
}

TEE_Result entry_invoke_command_sel4(unsigned long session_id,
			TEE_Param params[TEE_NUM_PARAMS], uint32_t param_types, unsigned long cmd_id)
{
	TEE_Result res;
	struct ta_session *session = ta_header_get_session(session_id);

	if (!session)
		return TEE_ERROR_BAD_STATE;

	ta_header_save_params(param_types, params);

	res = TA_InvokeCommandEntryPoint(session->session_ctx, cmd_id,
					 param_types, params);


	return res;
}
TEE_Result __utee_entry(unsigned long func, unsigned long session_id,
			struct utee_params *up, unsigned long cmd_id)
{
	TEE_Result res;

	switch (func) {
	case UTEE_ENTRY_FUNC_OPEN_SESSION:
		res = entry_open_session_sel4(session_id, up);
		break;
	case UTEE_ENTRY_FUNC_CLOSE_SESSION:
		res = entry_close_session_sel4(session_id);
		break;
	case UTEE_ENTRY_FUNC_INVOKE_COMMAND:
		res = entry_invoke_command2(session_id, up, cmd_id);
		break;
	default:
		res = 0xffffffff;
		TEE_Panic(0);
		break;
	}
	ta_header_save_params(0, NULL);

	return res;
}
