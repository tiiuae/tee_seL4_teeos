/*
 * Copyright 2022, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/* Local log level */
#define ZF_LOG_LEVEL ZF_LOG_INFO
// #define PLAINTEXT_DATA

#include <teeos/gen_config.h>

#include <regex.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>

#include <sel4runtime.h>
#include <sel4platsupport/platsupport.h>
#include <sel4utils/process.h>

#include <teeos_common.h>
#include <sys_ctl_service.h>

#include <utils/fence.h>
#include <utils/zf_log.h>

#include <ree_tee_msg.h>
#include <key_service.h>
#include <public_key.pem.h>

#include <crypto/crypto.h>
#include <tee/tee_fs_key_manager.h>
#include <sys_sel4.h>

#include <tee/tee_fs.h>

#define PARAM_NOT_USED  0

extern seL4_CPtr ipc_root_ep;
extern seL4_CPtr ipc_app_ep1;
extern void *app_shared_memory;

#define RSA_GUID_INDEX      0
#define ECC_GUID_INDEX      1
#define X25519_GUID_INDEX   2

#define KEY_BUF_SIZE    2048
#define FEK_SIZE        16u

#define  PK_PUBLIC      0x0000
   /* Refers to the private key */
#define PK_PRIVATE      0x0001
#define PK_STD          0x1000
#define IV_LENGTH       16

static const TEE_UUID uuid = {
                    0x5f8b97df, 0x2d0d, 0x4ad2,
                    {0x98, 0xd2, 0x74, 0xf4, 0x38, 0x27, 0x98, 0xbb},
                };

static uint8_t fek[FEK_SIZE];

#define RAMBD_HDR_MAGIC_V01     0x31305F64626D6172  /* 'r'a'm'b'd'_'0'1' */

struct rambd_ext_hdr {
    uint64_t magic;
    uint64_t ref_count;
    uint64_t buffer_len;
    uint64_t buffer_hash[TEE_SHA256_HASH_SIZE / sizeof(uint64_t)]; /* uint64_t alignment */
    uint64_t pad[1]; /* 16 byte alignment padding for AES */
    uint8_t buffer[0];
};

static struct rambd_ext_hdr *optee_ramdisk = NULL;

struct partial_import {
    void *buf;
    uint32_t received;
    uint32_t remaining;
};

static struct partial_import optee_import = { 0 };

static int generate_fek(uint8_t *buf)
{
    int err;
    err = get_serial_number(buf);
    if (!err)
    {
        err = tee_fs_fek_crypt(&uuid, TEE_MODE_ENCRYPT, buf, FEK_SIZE , buf);
    }
    return err;
}

int teeos_init_crypto(void)
{
    int err;

    err = crypto_init();
    if (err)
    {
        ZF_LOGI("Crypto init failed");
    }

    err = init_fortuna_rng();
    if (err)
    {
        ZF_LOGI("Fortuna RNG initializtion failed = %d", err);
    }

    err = tee_fs_init_key_manager();
    if (err)
    {
        ZF_LOGI("tee_fs_init_key_manager failed = %d", err);
    }

    err = generate_fek(fek);
    if (err)
    {
        ZF_LOGI("fek generation failed = %d", err);
    }
    return err;
}

int teeos_init_optee_storage(void)
{
    int ret = 0;
    uint32_t buf_len = 0;

    if (optee_ramdisk) {
        ZF_LOGI("ramdisk already initialized");
        return 0;
    }

    /* create an empty ramdisk */
    ret = ramdisk_fs_init(PARAM_NOT_USED, PARAM_NOT_USED,
                          sizeof(struct rambd_ext_hdr),
                          (void **)&optee_ramdisk, &buf_len);
    if (ret) {
        ZF_LOGE("ERROR: %d", ret);
        ret = -EIO;
    }

    /* setup external header */
    optee_ramdisk->magic = RAMBD_HDR_MAGIC_V01;
    optee_ramdisk->ref_count = 1; /* TODO: optee_ramdisk->ref_count = update_monotonic_counter() */
    /* ramdisk buffer size */
    optee_ramdisk->buffer_len = buf_len - sizeof(struct rambd_ext_hdr);

    return ret;
}

int teeos_reseed_fortuna_rng(void)
{
    return sys_reseed_fortuna_rng();
}

static int teeos_optee_calc_hash(uint8_t *data,
                                 uint32_t data_len,
                                 uint8_t *hash_out,
                                 uint32_t hash_len)
{
    int err = -1;

    TEE_Result tee_res = 0;
    void *hash_ctx = NULL;

    tee_res = crypto_hash_alloc_ctx(&hash_ctx, TEE_ALG_SHA256);
    if (tee_res) {
        ZF_LOGE("ERROR: hash_alloc_ctx: 0x%x", tee_res);
        err = -EIO;
        goto out;
    }

    tee_res = crypto_hash_init(hash_ctx);
    if (tee_res) {
        ZF_LOGE("ERROR: hash_init: 0x%x", tee_res);
        err = -EIO;
        goto out;
    }

    tee_res = crypto_hash_update(hash_ctx, data, data_len);
    if (tee_res) {
        ZF_LOGE("ERROR: hash_update: 0x%x", tee_res);
        err = -EIO;
        goto out;
    }

    tee_res = crypto_hash_final(hash_ctx,
                               hash_out,
                               hash_len);
    if (tee_res) {
        ZF_LOGE("ERROR: hash_final: 0x%x", tee_res);
        err = -EIO;
        goto out;
    }

    err = 0;

out:
    if (hash_ctx)
        crypto_hash_free_ctx(hash_ctx);

    return err;
}

int teeos_optee_export_storage(uint32_t storage_offset,
                               uint32_t *storage_len,
                               void *buf,
                               uint32_t buf_len,
                               uint32_t *export_len)
{
    int err = -1;
    uint32_t ramdisk_len = 0;
    uint32_t copy_len = 0;

    if (!storage_len || !buf || !export_len) {
        ZF_LOGF("ERROR: invalid parameter");
        return -EINVAL;
    }

    if (!optee_ramdisk) {
        ZF_LOGE("ERROR: ramdisk not created");
        return -EACCES;
    }

    /* header must be read with single command */
    if (storage_offset < sizeof(struct rambd_ext_hdr)) {
        if (storage_offset != 0) {
            ZF_LOGE("ERROR: invalid offset: %d", storage_offset);
            return -ESPIPE;
        }

        if (buf_len < sizeof(struct rambd_ext_hdr)) {
            ZF_LOGE("ERROR: invalid buffer len: %d", buf_len);
            return -EPERM;
        }
    }

    ramdisk_len = sizeof(struct rambd_ext_hdr) + optee_ramdisk->buffer_len;

    /* at minimum 1 byte returned */
    if (storage_offset >= ramdisk_len) {
        ZF_LOGE("ERROR: invalid offset: %d", storage_offset);
        return -ESPIPE;
    }

    /* update header before it is exported */
    if (storage_offset == 0) {
        err = teeos_optee_calc_hash(optee_ramdisk->buffer,
                                    optee_ramdisk->buffer_len,
                                    (uint8_t *)optee_ramdisk->buffer_hash,
                                    sizeof(optee_ramdisk->buffer_hash));
        if (err) {
            return err;
        }

        optee_ramdisk->ref_count++; /* TODO: optee_ramdisk->ref_count = update_monotonic_counter() */
    }

    copy_len = MIN(ramdisk_len - storage_offset, buf_len);

    memcpy(buf, (void*)optee_ramdisk + storage_offset, copy_len);

    *storage_len = ramdisk_len;
    *export_len = copy_len;

    ZF_LOGI("buff: %d, offset: %d, export: %d, storage: %d",
        buf_len, storage_offset, *export_len, *storage_len);

    return 0;
}

static int teeos_optee_import_storage_final(struct rambd_ext_hdr *ramdisk,
                                            uint32_t ramdisk_len)
{
    int err = -1;

    uint8_t hash[TEE_SHA256_HASH_SIZE] = { 0 } ;

    if (ramdisk->magic != RAMBD_HDR_MAGIC_V01) {
        ZF_LOGE("ERROR: bad magic: %ld", ramdisk->magic);
        return -EIO;
    }

    /* TODO: verify ramdisk->ref_count with monotonic counter value*/

    /* calc hash over received ramdisk and compare it with header value */
    err = teeos_optee_calc_hash(ramdisk->buffer,
                                        ramdisk->buffer_len,
                                        hash,
                                        sizeof(hash));
    if (err) {
        return err;
    }

    if (memcmp(hash, ramdisk->buffer_hash, sizeof(hash)) != 0) {
        ZF_LOGE("ERROR: hash mismatch");
        return -EACCES;
    }


    /* use imported storage data to create ramdisk */
    err = ramdisk_fs_init(ramdisk, ramdisk_len,
                          sizeof(struct rambd_ext_hdr),
                          PARAM_NOT_USED, PARAM_NOT_USED);
    if (err) {
        ZF_LOGE("ERROR: 0x%x", err);
        return -EIO;
    }

    return err;
}

int teeos_optee_import_storage(uint8_t *import, uint32_t import_len,
                                uint32_t storage_len)
{
    int ret = -1;

    if (optee_ramdisk) {
        ZF_LOGI("ERROR: ramdisk already initialized");
        return -EACCES;
    }

    /* allocate buffer for importing storage */
    if (!optee_import.buf) {
        ZF_LOGI("storage_len: %d", storage_len);

        optee_import.buf = calloc(1, storage_len);
        if (!optee_import.buf) {
            ZF_LOGE("ERROR: out of memory");
            return -ENOMEM;
        }

        optee_import.received = 0;
        optee_import.remaining = storage_len;
    }

    if (import_len > optee_import.remaining) {
        ZF_LOGE("ERROR: corrupted import: %d / %d",
            import_len, optee_import.remaining);
        ret = -EFAULT;
        goto err_out;
    }

    memcpy(optee_import.buf + optee_import.received, import, import_len);

    optee_import.received += import_len;
    optee_import.remaining -= import_len;

    ZF_LOGI("import: %d, pos: %d", import_len, optee_import.received);

    /* last import message, init ramdisk */
    if (optee_import.remaining == 0) {
        ZF_LOGI("Received complete storage: %d", optee_import.received);

        ret = teeos_optee_import_storage_final(optee_import.buf, optee_import.received);
        if (ret) {
            goto err_out;
        }

        optee_ramdisk = optee_import.buf;
    }

    return 0;

err_out:
    free(optee_import.buf);
    optee_import.buf = NULL;

    return ret;
}