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
#include <kernel/wait_queue.h>
#include <kernel/tee_time.h>
#include <crypto/crypto.h>

#include <sel4runtime.h>
#include <util.h>
#include <sys_ctl_service.h>
#include <sel4_teeos/gen_config.h>
#include <tommath.h>
#include <mempool.h>
#include "sys_sel4.h"

#include <utils/fence.h>
#include <utils/zf_log.h>
#include <tomcrypt.h>

prng_state sel4_prng;

struct thread_param;

struct bignum  {
   int used;
   int alloc;
   mp_sign sign;
   mp_digit *dp;
};

struct mutex {
    unsigned spin_lock;	/* used when operating on this struct */
    struct wait_queue wq;
    short state;		/* -1: write, 0: unlocked, > 0: readers */
};

int trace_level = TRACE_LEVEL;
const char trace_ext_prefix[]  = "";

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

    memcpy(buffer, uid, MIN(max_size_uid, len));
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

int init_fortuna_rng(void)
{
    int wprng = find_prng("fortuna");
    return rng_make_prng(256, wprng, &sel4_prng, NULL);
}

int sys_reseed_fortuna_rng(void)
{
    int ret;
    uint8_t random_data[32];
    ret = nonce_service(random_data);
    if (ret)
        return ret;
    ret = fortuna_update_seed(random_data, 32ul, &sel4_prng);
    return ret;
}


struct bignum *crypto_bignum_allocate(size_t size_bits)
{
    int err;
    struct bignum *A;
    A = malloc(sizeof(struct bignum));
    if (!A)
        return NULL;

    if (size_bits % sizeof(uint64_t))
    {
        DMSG("Unaligned bignumber allocation");
    }

    err = mp_init((void*)A);
    if (err)
    {
        EMSG("mp_init failed %d", err);
        free(A);
        return NULL;
    }
    err = mp_init_size((void*)A, size_bits/sizeof(uint64_t));
    if (err)
    {
        EMSG("mp_init_size failed %d", err);
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
            EMSG("mp_init failed %d", err);
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
        EMSG("%s failed : %d written = %lu",__func__, err,  written);
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
        EMSG("bignum copy failed %d", err);
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
    IMSG("%s %d", __func__, __LINE__);

    asm volatile(
        "rdtime %0"
        : "=r"(n));

    uint64_t timeinms = n/(CONFIG_HW_TIMER_FREQ / 1000UL);
    uint32_t seconds = (uint32_t)(n/CONFIG_HW_TIMER_FREQ);
    time->millis = timeinms % 1000;
    time->seconds = seconds;
    return 0;
}

uint32_t tee_time_get_sys_time_protection_level(void)
{
    IMSG("Not implemented %s", __func__);
    return 2;
}

void tee_time_wait(uint32_t milliseconds_delay)
{
    IMSG("Not implemented %s", __func__);
}

TEE_Result tee_time_get_ree_time(TEE_Time *time)
{
    time->millis = 300;
    time->seconds = 2000;
    IMSG("Not implemented %s", __func__);
    return 2;
}


void free_wipe(void *ptr)
{
    free(ptr);
}

void mutex_unlock(struct mutex *m)
{
    DMSG("Not implemented %s", __func__);
    m = m;
}
void mutex_lock(struct mutex *m)
{
    DMSG("Not implemented %s", __func__);
    m = m;
}

uint8_t ta_heap[16 * 1024];
const size_t ta_heap_size = sizeof(ta_heap);
const size_t ta_num_props = 8;

uint32_t thread_rpc_cmd(uint32_t cmd, size_t num_params,
            struct thread_param *params)
{
    IMSG("Not implemented %s", __func__);
    return 0;
}

size_t strlcpy(char *dst, const char *src, size_t siz)
{
    register char *d = dst;
    register const char *s = src;
    register size_t n = siz;

    /* Copy as many bytes as will fit */
    if (n != 0 && --n != 0) {
        do {
            if ((*d++ = *s++) == 0)
                break;
        } while (--n != 0);
    }

    /* Not enough room in dst, add NUL and traverse rest of src */
    if (n == 0) {
        if (siz != 0)
            *d = '\0';	/* NUL-terminate dst */
        while (*s++)
            ;
    }

    return s - src - 1;	/* count does not include NUL */
}