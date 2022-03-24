/*
 * Copyright 2022, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <trace.h>
#include <tee_api_types.h>
#include <sys/queue.h>
#include <crypto.h>
#include <utee_syscalls.h>
#include <tee/tee_svc.h>
#include <tee/tee_svc_cryp.h>
#include <tee/tee_svc_storage.h>
#include <kernel/user_mode_ctx_struct.h>
#include <kernel/tee_time.h>
#include "sys_sel4.h"

#include <utils/zf_log.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wcast-qual"

#define UNREACHABLE()       __builtin_unreachable()

/* We support only one session at time */
static struct ts_session local_session;

void _utee_return(unsigned long ret)
{
    (void)ret;
}

void _utee_log(const void *buf, size_t len)
{
    syscall_log(buf,len);
}

/* This is not __noreturn because AArch32 stack unwinding fails otherwise */
void _utee_panic(unsigned long code)
{
    EMSG("PANIC Not implemented %s  code %lu ", __func__, code);
}

/* prop_set is TEE_PROPSET_xxx*/
TEE_Result _utee_get_property(unsigned long prop_set, unsigned long index,
                  void *name, uint32_t *name_len, void *buf,
                  uint32_t *blen, uint32_t *prop_type)
{
    return syscall_get_property(prop_set, index,name, name_len, buf, blen, prop_type);
}

TEE_Result _utee_get_property_name_to_index(unsigned long prop_set,
                        const void *name,
                        unsigned long name_len,
                        uint32_t *index)
{
    return syscall_get_property_name_to_index(prop_set, (void*)name, name_len, index);
}

/* sess has type TEE_TASessionHandle */
TEE_Result _utee_open_ta_session(const TEE_UUID *dest,
                 unsigned long cancel_req_to,
                 struct utee_params *params, uint32_t *sess,
                 uint32_t *ret_orig)
{
    EMSG("Not implemented %s ", __func__);
    return 0;
}

/* sess has type TEE_TASessionHandle */
TEE_Result _utee_close_ta_session(unsigned long sess)
{
    EMSG("Not implemented %s ", __func__);
    return 0;
}

/* sess has type TEE_TASessionHandle */
TEE_Result _utee_invoke_ta_command(unsigned long sess,
                   unsigned long cancel_req_to,
                   unsigned long cmd_id,
                   struct utee_params *params,
                   uint32_t *ret_orig)
{
    EMSG("Not implemented %s ", __func__);
    return 0;
}

TEE_Result _utee_check_access_rights(uint32_t flags, const void *buf,
                     size_t len)
{
    IMSG("Not implemented %s ", __func__);
    return 0;
}

/* cancel has type bool */
TEE_Result _utee_get_cancellation_flag(uint32_t *cancel)
{
    IMSG("Not implemented %s ", __func__);
    return 0;
}

/* old_mask has type bool */
TEE_Result _utee_unmask_cancellation(uint32_t *old_mask)
{
    IMSG("Not implemented %s ", __func__);
    return 0;
}

/* old_mask has type bool */
TEE_Result _utee_mask_cancellation(uint32_t *old_mask)
{
    IMSG("Not implemented %s ", __func__);
    return 0;
}

TEE_Result _utee_wait(unsigned long timeout)
{
    return syscall_wait(timeout);
}

/* cat has type enum _utee_time_category */
TEE_Result _utee_get_time(unsigned long cat, TEE_Time *time)
{
    EMSG("Not implemented %s ", __func__);
    return 0;
}

TEE_Result _utee_set_ta_time(const TEE_Time *time)
{
    EMSG("Not implemented %s ", __func__);
    return 0;
}

TEE_Result _utee_cryp_state_alloc(unsigned long algo, unsigned long op_mode,
                  unsigned long key1, unsigned long key2,
                  uint32_t *state)
{
    return syscall_cryp_state_alloc(algo, op_mode, key1, key2, state);

}
TEE_Result _utee_cryp_state_copy(unsigned long dst, unsigned long src)
{
    return syscall_cryp_state_copy(dst, src);
}
TEE_Result _utee_cryp_state_free(unsigned long state)
{
    return syscall_cryp_state_free(state);
}

/* iv and iv_len are ignored for some algorithms */
TEE_Result _utee_hash_init(unsigned long state, const void *iv, size_t iv_len)
{
    return syscall_hash_init(state, iv, iv_len);
}
TEE_Result _utee_hash_update(unsigned long state, const void *chunk,
                 size_t chunk_size)
{
    return syscall_hash_update(state, chunk, chunk_size);
}
TEE_Result _utee_hash_final(unsigned long state, const void *chunk,
                size_t chunk_size, void *hash, uint64_t *hash_len)
{
    return syscall_hash_final(state, chunk, chunk_size, hash, hash_len);
}

TEE_Result _utee_cipher_init(unsigned long state, const void *iv,
                 size_t iv_len)
{
    return syscall_cipher_init(state, iv, iv_len);
}
TEE_Result _utee_cipher_update(unsigned long state, const void *src,
                   size_t src_len, void *dest, uint64_t *dest_len)
{
    return syscall_cipher_update(state, src, src_len, dest, dest_len);
}


TEE_Result _utee_cipher_final(unsigned long state, const void *src,
                  size_t src_len, void *dest, uint64_t *dest_len)
{
    return syscall_cipher_final(state, src, src_len, dest, dest_len);
}

/* Generic Object Functions */
TEE_Result _utee_cryp_obj_get_info(unsigned long obj, TEE_ObjectInfo *info)
{
    return syscall_cryp_obj_get_info(obj, info);
}
TEE_Result _utee_cryp_obj_restrict_usage(unsigned long obj,
                     unsigned long usage)
{
    return syscall_cryp_obj_restrict_usage(obj, usage);
}
TEE_Result _utee_cryp_obj_get_attr(unsigned long obj, unsigned long attr_id,
                   void *buffer, uint64_t *size)
{
    return syscall_cryp_obj_get_attr(obj,attr_id, buffer, size );
}

/* Transient Object Functions */
/* type has type TEE_ObjectType */
TEE_Result _utee_cryp_obj_alloc(unsigned long type, unsigned long max_size,
                uint32_t *obj)
{
    return syscall_cryp_obj_alloc(type, max_size, obj);
}
TEE_Result _utee_cryp_obj_close(unsigned long obj)
{
    return syscall_cryp_obj_close(obj);
}
TEE_Result _utee_cryp_obj_reset(unsigned long obj)
{
    return syscall_cryp_obj_reset(obj);
}
TEE_Result _utee_cryp_obj_populate(unsigned long obj,
                   struct utee_attribute *attrs,
                   unsigned long attr_count)
{
    return syscall_cryp_obj_populate(obj,attrs, attr_count);
}
TEE_Result _utee_cryp_obj_copy(unsigned long dst_obj, unsigned long src_obj)
{
    return syscall_cryp_obj_copy(dst_obj, src_obj);
}

TEE_Result _utee_cryp_obj_generate_key(unsigned long obj,
                       unsigned long key_size,
                       const struct utee_attribute *params,
                       unsigned long param_count)
{
    return syscall_obj_generate_key(obj, key_size, params, param_count);
}

TEE_Result _utee_cryp_derive_key(unsigned long state,
                 const struct utee_attribute *params,
                 unsigned long param_count,
                 unsigned long derived_key)
{
    return syscall_cryp_derive_key(state, params, param_count,derived_key);
}

TEE_Result _utee_cryp_random_number_generate(void *buf, size_t blen)
{
    return syscall_cryp_random_number_generate(buf,blen);
}

TEE_Result _utee_authenc_init(unsigned long state, const void *nonce,
                  size_t nonce_len, size_t tag_len, size_t aad_len,
                  size_t payload_len)
{
    return syscall_authenc_init(state, nonce, nonce_len, tag_len, aad_len, payload_len);
}
TEE_Result _utee_authenc_update_aad(unsigned long state, const void *aad_data,
                    size_t aad_data_len)
{
    return syscall_authenc_update_aad(state, aad_data, aad_data_len);
}
TEE_Result _utee_authenc_update_payload(unsigned long state,
                    const void *src_data, size_t src_len,
                    void *dest_data, uint64_t *dest_len)
{
    return syscall_authenc_update_payload(state, src_data, src_len, dest_data, dest_len);
}
TEE_Result _utee_authenc_enc_final(unsigned long state, const void *src_data,
                   size_t src_len, void *dest_data,
                   uint64_t *dest_len, void *tag,
                   uint64_t *tag_len)
{
    return syscall_authenc_enc_final(state, src_data, src_len, dest_data, dest_len,
                                       tag, tag_len);
}
TEE_Result _utee_authenc_dec_final(unsigned long state, const void *src_data,
                   size_t src_len, void *dest_data,
                   uint64_t *dest_len, const void *tag,
                   size_t tag_len)
{
    return syscall_authenc_dec_final(state, src_data, src_len, dest_data, dest_len,
                                       tag, tag_len);
}

TEE_Result _utee_asymm_operate(unsigned long state,
                   const struct utee_attribute *params,
                   unsigned long num_params, const void *src_data,
                   size_t src_len, void *dest_data,
                   uint64_t *dest_len)
{
    return syscall_asymm_operate(state, params, num_params, src_data, src_len,
                                dest_data, dest_len);
}

TEE_Result _utee_asymm_verify(unsigned long state,
                  const struct utee_attribute *params,
                  unsigned long num_params, const void *data,
                  size_t data_len, const void *sig, size_t sig_len)
{
    return syscall_asymm_verify(state, params, num_params, data, data_len, sig, sig_len);
}

/* Persistant Object Functions */
/* obj is of type TEE_ObjectHandle */
TEE_Result _utee_storage_obj_open(unsigned long storage_id,
                  const void *object_id, size_t object_id_len,
                  unsigned long flags, uint32_t *obj)

{
    return syscall_storage_obj_open(storage_id, (void*)object_id, object_id_len, flags, obj);
}

/*
 * attr is of type TEE_ObjectHandle
 * obj is of type TEE_ObjectHandle
 */
TEE_Result _utee_storage_obj_create(unsigned long storage_id,
                    const void *object_id,
                    size_t object_id_len, unsigned long flags,
                    unsigned long attr, const void *data,
                    size_t len, uint32_t *obj)
{
    return syscall_storage_obj_create(storage_id, (void*)object_id, object_id_len,
                                flags, attr, (void*)data, len, obj);
}

/* obj is of type TEE_ObjectHandle */
TEE_Result _utee_storage_obj_del(unsigned long obj)
{
    return syscall_storage_obj_del(obj);
}
/* obj is of type TEE_ObjectHandle */
TEE_Result _utee_storage_obj_rename(unsigned long obj, const void *new_obj_id,
                    size_t new_obj_id_len)
{
    return syscall_storage_obj_rename(obj, (void*)new_obj_id, new_obj_id_len);
}

/* Persistent Object Enumeration Functions */
/* obj_enum is of type TEE_ObjectEnumHandle */
TEE_Result _utee_storage_alloc_enum(uint32_t *obj_enum)
{
    EMSG("Not implemented %s ", __func__);
    return 0;
}

/* obj_enum is of type TEE_ObjectEnumHandle */
TEE_Result _utee_storage_free_enum(unsigned long obj_enum)
{
    EMSG("Not implemented %s ", __func__);
    return 0;
}

/* obj_enum is of type TEE_ObjectEnumHandle */
TEE_Result _utee_storage_reset_enum(unsigned long obj_enum)
{
    EMSG("Not implemented %s ", __func__);
    return 0;
}

/* obj_enum is of type TEE_ObjectEnumHandle */
TEE_Result _utee_storage_start_enum(unsigned long obj_enum,
                    unsigned long storage_id)
{
    EMSG("Not implemented %s ", __func__);
    return 0;
}

/* obj_enum is of type TEE_ObjectEnumHandle */
TEE_Result _utee_storage_next_enum(unsigned long obj_enum, TEE_ObjectInfo *info,
                   void *obj_id, uint64_t *len)
{
    return syscall_storage_next_enum(obj_enum, info, obj_id, len);
}

/* Data Stream Access Functions */
/* obj is of type TEE_ObjectHandle */
TEE_Result _utee_storage_obj_read(unsigned long obj, void *data, size_t len,
                  uint64_t *count)
{
    return syscall_storage_obj_read(obj, data, len, count);
}

/* obj is of type TEE_ObjectHandle */
TEE_Result _utee_storage_obj_write(unsigned long obj, const void *data,
                   size_t len)
{
    return syscall_storage_obj_write(obj, (void*)data, len);

}

/* obj is of type TEE_ObjectHandle */
TEE_Result _utee_storage_obj_trunc(unsigned long obj, size_t len)
{
    return syscall_storage_obj_trunc(obj, len);
}

/* obj is of type TEE_ObjectHandle */
/* whence is of type TEE_Whence */
TEE_Result _utee_storage_obj_seek(unsigned long obj, int32_t offset,
                  unsigned long whence)
{
    return syscall_storage_obj_seek(obj, offset, whence);
}

/* seServiceHandle is of type TEE_SEServiceHandle */
TEE_Result _utee_se_service_open(uint32_t *seServiceHandle)
{
    EMSG("Not implemented %s ", __func__);
    return 0;
}

/* seServiceHandle is of type TEE_SEServiceHandle */
TEE_Result _utee_se_service_close(unsigned long seServiceHandle)
{
    EMSG("Not implemented %s ", __func__);
    return 0;
}

/*
 * seServiceHandle is of type TEE_SEServiceHandle
 * r is of type TEE_SEReaderHandle
 */
TEE_Result _utee_se_service_get_readers(unsigned long seServiceHandle,
                    uint32_t *r, uint64_t *len)
{
    EMSG("Not implemented %s ", __func__);
    return 0;
}

/*
 * r is of type TEE_SEReaderHandle
 * p is defined with defines UTEE_SE_READER_*
 */
TEE_Result _utee_se_reader_get_prop(unsigned long r, uint32_t *p)
{
    EMSG("Not implemented %s ", __func__);
    return 0;
}

/* r is of type TEE_SEReaderHandle */
TEE_Result _utee_se_reader_get_name(unsigned long r, char *name,
                    uint64_t *name_len)
{
    EMSG("Not implemented %s ", __func__);
    return 0;
}

/*
 * r is of type TEE_SEReaderHandle
 * s if of type TEE_SESessionHandle
 */
TEE_Result _utee_se_reader_open_session(unsigned long r, uint32_t *s)
{
    EMSG("Not implemented %s ", __func__);
    return 0;
}

/* r is of type TEE_SEReaderHandle */
TEE_Result _utee_se_reader_close_sessions(unsigned long r)
{
    EMSG("Not implemented %s ", __func__);
    return 0;
}

/* s is of type TEE_SESessionHandle */
TEE_Result _utee_se_session_is_closed(unsigned long s)
{
    EMSG("Not implemented %s ", __func__);
    return 0;
}

/* s is of type TEE_SESessionHandle */
TEE_Result _utee_se_session_get_atr(unsigned long s, void *atr,
                    uint64_t *atr_len)
{
    EMSG("Not implemented %s ", __func__);
    return 0;
}

/*
 * s is of type TEE_SESessionHandle
 * c is of type TEE_SEChannelHandle
 */
TEE_Result _utee_se_session_open_channel(unsigned long s,
                     unsigned long is_logical,
                     const void *aid_buffer,
                     size_t aid_buffer_len, uint32_t *c)
{
    EMSG("Not implemented %s ", __func__);
    return 0;
}

/* s is of type TEE_SESessionHandle */
TEE_Result _utee_se_session_close(unsigned long s)
{
    EMSG("Not implemented %s ", __func__);
    return 0;
}

/* c is of type TEE_SEChannelHandle */
TEE_Result _utee_se_channel_select_next(unsigned long c)
{
    EMSG("Not implemented %s ", __func__);
    return 0;
}

/* c is of type TEE_SEChannelHandle */
TEE_Result _utee_se_channel_get_select_resp(unsigned long c, void *resp,
                        uint64_t *resp_len)
{
    EMSG("Not implemented %s ", __func__);
    return 0;
}

/* c is of type TEE_SEChannelHandle */
TEE_Result _utee_se_channel_transmit(unsigned long c, void *cmd, size_t cmd_len,
                     void *resp, uint64_t *resp_len)
{
    EMSG("Not implemented %s ", __func__);
    return 0;
}

/* c is of type TEE_SEChannelHandle */
TEE_Result _utee_se_channel_close(unsigned long c)
{
    EMSG("Not implemented %s ", __func__);
    return 0;
}

/* op is of type enum _utee_cache_operation */
TEE_Result _utee_cache_operation(void *va, size_t l, unsigned long op)
{
    EMSG("Not implemented %s ", __func__);
    return 0;
}

TEE_Result _utee_gprof_send(void *buf, size_t size, uint32_t *id)
{
    EMSG("Not implemented %s ", __func__);
    return 0;
}

/* Misc */
TEE_Result vm_check_access_rights(const struct user_mode_ctx *uctx,
                  uint32_t flags, uaddr_t uaddr, size_t len)
{
    DMSG("Not implemented %s ", __func__);
    return TEE_SUCCESS;
}


TEE_Result copy_to_user_private(void *uaddr, const void *kaddr, size_t len)
{
    memcpy(uaddr, kaddr, len);
    return 0;
}
TEE_Result copy_to_user(void *uaddr, const void *kaddr, size_t len)
{
    memcpy(uaddr, kaddr, len);
    return 0;
}

vaddr_t uref_to_vaddr(uint64_t uref)
{
    return (vaddr_t)uref;
}

uint64_t kaddr_to_uref(void *kaddr)
{
    return(vaddr_t)kaddr;
}
#ifdef CFG_WITH_USER_TA

TEE_Result copy_from_user(void *kaddr, const void *uaddr, size_t len)
{
    memcpy(kaddr, uaddr, len);
    return 0;
}

TEE_Result copy_from_user_private(void *kaddr, const void *uaddr, size_t len)
{
    memcpy(kaddr, uaddr, len);
    return 0;
}
#endif
TEE_Result copy_kaddr_to_uref(uint32_t *uref, void *kaddr)
{
    uint64_t ref = kaddr_to_uref(kaddr);
    if (ref > UINT32_MAX) {
        ZF_LOGF("Kaddr pointer value too large %p", kaddr);
    }

    return copy_to_user_private(uref, &ref, sizeof(uint32_t));
}

/* Sessopm stuff */

struct tee_ta_session *__noprof to_ta_session(struct ts_session *sess)
{
    return container_of(sess, struct tee_ta_session, ts_sess);
}

void ts_push_current_session(struct ts_session *s)
{
    DMSG("Not propely implemented %s ", __func__);
    memcpy(&local_session, s , sizeof(struct ts_session));
}

struct ts_session *ts_pop_current_session(void)
{
    DMSG("Not propely implemented %s ", __func__);
    return &local_session;
}

struct ts_session *ts_get_calling_session(void)
{
    DMSG("Not properly implemented %s ", __func__);
    return &local_session;
    }

struct ts_session *ts_get_current_session_may_fail(void)
{
    DMSG("Not properly implemented %s ", __func__);
    return &local_session;
}

struct ts_session *ts_get_current_session(void)
{
    DMSG("Not properly implemented %s ", __func__);
    return &local_session;
}

bool tee_ta_session_is_cancelled(struct tee_ta_session *s, TEE_Time *curr_time)
{
    TEE_Time current_time;

    if (s->cancel_mask)
        return false;

    if (s->cancel)
        return true;

    if (s->cancel_time.seconds == UINT32_MAX)
        return false;

    if (curr_time != NULL)
        current_time = *curr_time;
    else if (tee_time_get_sys_time(&current_time) != TEE_SUCCESS)
        return false;

    if (current_time.seconds > s->cancel_time.seconds ||
        (current_time.seconds == s->cancel_time.seconds &&
         current_time.millis >= s->cancel_time.millis)) {
        return true;
    }

    return false;
}


#pragma GCC diagnostic pop