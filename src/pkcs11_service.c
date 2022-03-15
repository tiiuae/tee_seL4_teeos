/*
 * Copyright 2022, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/* Local log level */
#define ZF_LOG_LEVEL ZF_LOG_INFO

#include <teeos/gen_config.h>

#include <regex.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <stdint.h>

#include <sel4runtime.h>
#include <teeos_common.h>
#include <sys_ctl_service.h>

#include <utils/fence.h>
#include <utils/zf_log.h>

#include <ree_tee_msg.h>
#include <sys_sel4.h>

#include <crypto/crypto.h>
#include <tee/tee_fs_key_manager.h>

#include <utee_syscalls.h>
#include <user_ta_header.h>
#include <kernel/user_ta.h>
#include <pkcs11_ta.h>
#include <pkcs11_token.h>
#include <kernel/ts_manager.h>
#include <kernel/tee_ta_manager.h>


/*globals*/

#define PKCS11_SESSION_ID 1


#define TA_UUID             PKCS11_TA_UUID

#define TA_FLAGS     (TA_FLAG_SINGLE_INSTANCE | \
                     TA_FLAG_MULTI_SESSION | \
                     TA_FLAG_INSTANCE_KEEP_ALIVE)

#define TA_STACK_SIZE           (4 * 1024)

#define TA_DATA_SIZE            CFG_PKCS11_TA_HEAP_SIZE

#define TA_DESCRIPTION          "PKCS#11 trusted application"
#define TA_VERSION  TO_STR(PKCS11_TA_VERSION_MAJOR) "." \
                    TO_STR(PKCS11_TA_VERSION_MINOR) "." \
                    TO_STR(PKCS11_TA_VERSION_PATCH)

#define TA_FRAMEWORK_STACK_SIZE 2048

const struct ta_head ta_head  = {
    /* UUID, unique to each TA */
    .uuid = TA_UUID,
    /*
     * According to GP Internal API, TA_FRAMEWORK_STACK_SIZE corresponds to
     * the stack size used by the TA code itself and does not include stack
     * space possibly used by the Trusted Core Framework.
     * Hence, stack_size which is the size of the stack to use,
     * must be enlarged
     */
    .stack_size = TA_STACK_SIZE + TA_FRAMEWORK_STACK_SIZE,
    .flags = TA_FLAGS,
    /*
     * The TA entry doesn't go via this field any longer, to be able to
     * reliably check that an old TA isn't loaded set this field to a
     * fixed value.
     */
    .depr_entry = UINT64_MAX,
};

const struct user_ta_property ta_props[] = {
    {TA_PROP_STR_SINGLE_INSTANCE, USER_TA_PROP_TYPE_BOOL,
     &(const bool){(TA_FLAGS & TA_FLAG_SINGLE_INSTANCE) != 0}},

    {TA_PROP_STR_MULTI_SESSION, USER_TA_PROP_TYPE_BOOL,
     &(const bool){(TA_FLAGS & TA_FLAG_MULTI_SESSION) != 0}},

    {TA_PROP_STR_KEEP_ALIVE, USER_TA_PROP_TYPE_BOOL,
     &(const bool){(TA_FLAGS & TA_FLAG_INSTANCE_KEEP_ALIVE) != 0}},

    {TA_PROP_STR_DATA_SIZE, USER_TA_PROP_TYPE_U32,
     &(const uint32_t){TA_DATA_SIZE}},

    {TA_PROP_STR_STACK_SIZE, USER_TA_PROP_TYPE_U32,
     &(const uint32_t){TA_STACK_SIZE}},

    {TA_PROP_STR_VERSION, USER_TA_PROP_TYPE_STRING,
     TA_VERSION},

    {TA_PROP_STR_DESCRIPTION, USER_TA_PROP_TYPE_STRING,
     TA_DESCRIPTION},

/*
 * Extended propietary properties, name of properties must not begin with
 * "gpd."
 */
#ifdef TA_CURRENT_TA_EXT_PROPERTIES
    TA_CURRENT_TA_EXT_PROPERTIES
#endif
};

static struct utee_params up;
static uint32_t session_handle;

/* For testing purposes hard coded params for pkcs11 TA */
static void ping_params(TEE_Param params[TEE_NUM_PARAMS], uint32_t *param_types, uint32_t *cmd)
{

*param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_MEMREF_OUTPUT,
                        TEE_PARAM_TYPE_NONE);

    static uint32_t ret_value;
    static uint8_t p[12];
    params[0].memref.size = sizeof(uint32_t);
    params[0].memref.buffer = &ret_value;
    params[2].memref.size = 12;
    params[2].memref.buffer = &p;

    *cmd = PKCS11_CMD_PING;
}

static void open_session_params(TEE_Param params[TEE_NUM_PARAMS], uint32_t *param_types, uint32_t *cmd)
{
    *param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_MEMREF_OUTPUT,
                        TEE_PARAM_TYPE_NONE);

static uint32_t ret_value[2];
    ret_value[1] = (PKCS11_CKFSS_RW_SESSION | PKCS11_CKFSS_SERIAL_SESSION);

    params[0].memref.size = sizeof(uint32_t) * 2;
    params[0].memref.buffer = ret_value;
    params[2].memref.size = 4;
    params[2].memref.buffer = &session_handle;


    *cmd = PKCS11_CMD_OPEN_SESSION;
}

static void generate_random(TEE_Param params[TEE_NUM_PARAMS], uint32_t *param_types, uint32_t *cmd)
{
    *param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_MEMREF_OUTPUT,
                        TEE_PARAM_TYPE_NONE);

    uint32_t p = session_handle;
    params[0].memref.size = sizeof(uint32_t);
    params[0].memref.buffer = &p;

    *cmd = PKCS11_CMD_GENERATE_RANDOM;
}

static void close_session(TEE_Param params[TEE_NUM_PARAMS], uint32_t *param_types, uint32_t *cmd)
{
    *param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE);


    params[0].memref.size = sizeof(uint32_t);
    params[0].memref.buffer = &session_handle;

    *cmd = PKCS11_CMD_CLOSE_SESSION;
}

static void slot_info_params(TEE_Param params[TEE_NUM_PARAMS], uint32_t *param_types, uint32_t *cmd)
{
    *param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_MEMREF_OUTPUT,
                        TEE_PARAM_TYPE_NONE);

    static uint32_t ret_value[3] = {0};
    static struct pkcs11_slot_info p;

    params[0].memref.size = sizeof(uint32_t);
    params[0].memref.buffer = ret_value;
    params[2].memref.size = sizeof(struct pkcs11_slot_info);
    params[2].memref.buffer = &p;


    *cmd = PKCS11_CMD_SLOT_INFO;
}



struct ts_ctx *ctx;

int sel4_init_pkcs11_session()
{
    int ret;
    ZF_LOGI("\n\n INIT PKCS 11 \n\n");
    init_sel4_mempool();

    ctx = malloc(sizeof(struct ts_ctx));

    struct tee_ta_session *ses = calloc(1, sizeof(struct tee_ta_session));
    ses->cancel_mask = true;
    ses->lock_thread = 2;
    ses->ref_count = 1;

    const TEE_UUID tuid = TA_UUID;

    ret = tee_ta_init_user_ta_session(&tuid, ses);
    if (ret)
    {
        ZF_LOGI("tee_ta_init_user_ta_session failed %d", ret);
    }

    ret = TA_CreateEntryPoint();
    if (ret)
    {
        ZF_LOGI("TA_CreateEntryPoint failed %d", ret);
    }

    ret = entry_open_session_sel4(PKCS11_SESSION_ID , &up);

    if (ret)
    {
        ZF_LOGI("entry_open_session_sel4 %d", ret);
    }

    return ret;

}

int sel4_execute_pkcs11_command(TEE_Param params[TEE_NUM_PARAMS], uint32_t paramstype, uint32_t cmd)
{
    int ret;


    ZF_LOGI("\n \033[0;35m INVOKE COMMAND %u \033[0m", cmd);
    ret = entry_invoke_command_sel4(PKCS11_SESSION_ID, params, paramstype, cmd);

    return ret;
}

int sel4_close_pkcs11_session(void)
{
    return entry_close_session_sel4(PKCS11_SESSION_ID);
}


int test_pkcs11(void)
{
    int ret;
    uint32_t param_types;
    TEE_Param params[TEE_NUM_PARAMS] = {0};
    uint32_t cmd;

    ZF_LOGI("PKCS11 DEMO \n");
    ret = sel4_init_pkcs11_session();
    ZF_LOGI("Init PKCS11 session result %d", ret);

    open_session_params(params, &param_types, &cmd);
    ret = sel4_execute_pkcs11_command(params ,param_types ,cmd);
    ZF_LOGI("Invoke PKCS11 session result %d", ret);

    ping_params(params, &param_types, &cmd);
    ret = sel4_execute_pkcs11_command(params ,param_types ,cmd);
    ZF_LOGI("Invoke PKCS11 session result %d", ret);

    slot_info_params(params, &param_types, &cmd);
    ret = sel4_execute_pkcs11_command(params ,param_types ,cmd);
    ZF_LOGI("Invoke PKCS11 session result %d", ret);

    generate_random(params ,&param_types ,&cmd);
    ret = sel4_execute_pkcs11_command(params ,param_types ,cmd);
    ZF_LOGI("Invoke PKCS11 session result %d", ret);

    close_session(params ,&param_types ,&cmd);
    ret = sel4_execute_pkcs11_command(params ,param_types ,cmd);
    ZF_LOGI("Invoke PKCS11 session result %d", ret);



    ret = sel4_close_pkcs11_session();
    ZF_LOGI("Close PKCS11 session result %d", ret);
    return ret;
}