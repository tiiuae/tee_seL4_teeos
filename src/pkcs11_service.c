/*
 * Copyright 2022, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/* Local log level */
#define ZF_LOG_LEVEL ZF_LOG_ERROR

#include <sel4_teeos/gen_config.h>

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
#include <key_service.h>
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
struct ts_ctx *ctx;

int sel4_init_pkcs11_session()
{
    int ret;
    ZF_LOGI("\n\n Open PKCS11 Session \n\n");

    ret = entry_open_session_sel4(PKCS11_SESSION_ID , &up);
    if (ret)
    {
        ZF_LOGE("entry_open_session_sel4 failed %d", ret);
    }

    return ret;
}

int teeos_init_optee(void)
{
    int ret;

    ctx = malloc(sizeof(struct ts_ctx));

    struct tee_ta_session *ses = calloc(1, sizeof(struct tee_ta_session));
    ses->cancel_mask = true;
    ses->lock_thread = 2;
    ses->ref_count = 1;

    const TEE_UUID tuid = TA_UUID;

    ret = tee_ta_init_user_ta_session(&tuid, ses);
    if (ret)
    {
        ZF_LOGE("tee_ta_init_user_ta_session failed %d", ret);
    }

    /* Init Ramdisk */
    ret = teeos_init_optee_storage();
    if (ret) {
         ZF_LOGE("teeos_init_optee_storage failed %d", ret);
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
