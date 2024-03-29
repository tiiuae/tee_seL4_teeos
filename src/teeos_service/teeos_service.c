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
#include <stdint.h>
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
#include <teeos_service.h>
#include <public_key.pem.h>

#include <crypto/crypto.h>
#include <tee/tee_fs_key_manager.h>
#include <sys_sel4.h>

#include <tee/tee_fs.h>

#define PARAM_NOT_USED  0

#define IV_SIZE         16u
#define NVM_PAGE_COUNTER 128
enum counter_t {
    FS_MONOTONIC = 1,
    INVALID = 100,
};

static const TEE_UUID uuid = {
                    0x5f8b97df, 0x2d0d, 0x4ad2,
                    {0x98, 0xd2, 0x74, 0xf4, 0x38, 0x27, 0x98, 0xbb},
                };

static uint8_t sel4_fek[FEK_SIZE];
static void *fs_ctx = NULL;

#define RAMBD_HDR_MAGIC_V01     0x31305F64626D6172  /* 'r'a'm'b'd'_'0'1' */

struct rambd_ext_hdr {
    uint8_t iv[IV_SIZE]; /*16 byte IV for aes, this is not encrypted */
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

static uint8_t nvm_page[NVM_PAGE_SIZE];
struct nvm_counter {
    uint64_t fs_monotonic_counter;
    uint64_t aux_counter;
};

static int read_counter(enum counter_t counter_id, uint64_t *value)
{
    int ret = -1;
    uint32_t admin_data;

    switch (counter_id)
    {
    case FS_MONOTONIC:
        {
            ret = secure_nvm_read(NVM_PAGE_COUNTER, NULL, (uint8_t*)&admin_data, nvm_page, NVM_PAGE_SIZE);
            struct nvm_counter *counter = (struct nvm_counter*)nvm_page;
            *value = counter->fs_monotonic_counter;
        }
        break;

    default:
        return -EINVAL;
    }
    return ret;
}

static int write_counter(enum counter_t counter_id, uint64_t value)
{
    int ret = -1;

    switch (counter_id)
    {
    case FS_MONOTONIC:
        {
            struct nvm_counter *counter = (struct nvm_counter*)nvm_page;
            counter->fs_monotonic_counter = value;
            ret = secure_nvm_write(MSS_SYS_SNVM_NON_AUTHEN_TEXT_REQUEST_CMD, NVM_PAGE_COUNTER,
                                            nvm_page,NULL);
        }
        break;

    default:
        return -EINVAL;
    }
    return ret;
}


static int generate_fek(uint8_t *buf)
{
    int err;
    uint8_t puf_resp[32];
    /* Use serial number as a challenge for puf*/
    err = get_serial_number(buf);
    if (err)
        return err;
    /* Use PUF as a key */
    err = puf_emulation_service(buf,PUF_FEK_INDEX, puf_resp);
    if (!err)
    {
        err = tee_fs_fek_crypt(&uuid, TEE_MODE_ENCRYPT, puf_resp, FEK_SIZE , buf);
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

    err = generate_fek(sel4_fek);
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

static int tee_fs_crypt_init(TEE_OperationMode mode, void **ctx, uint8_t *decrypt_iv)
{
    int res;
    uint8_t fek[TEE_FS_KM_FEK_SIZE];
    uint8_t rand[32];
    uint8_t *iv;

    ZF_LOGI("%scrypt init", (mode == TEE_MODE_ENCRYPT) ? "En" : "De");

    /* Decrypt FEK */
    res = tee_fs_fek_crypt(&uuid, TEE_MODE_DECRYPT, sel4_fek,
                   TEE_FS_KM_FEK_SIZE, fek);
    if (res != TEE_SUCCESS)
        return res;

    if (mode == TEE_MODE_ENCRYPT) {
        iv = optee_ramdisk->iv;
        /* Use random number as IV and store it to ramdisk image header */
        nonce_service(rand);
        memcpy(iv, rand, TEE_AES_BLOCK_SIZE);
    } else {
        iv = decrypt_iv;
    }

    res = crypto_cipher_alloc_ctx(ctx, TEE_ALG_AES_CBC_NOPAD);
    if (res != TEE_SUCCESS)
        return res;

    res = crypto_cipher_init(*ctx, mode, fek, sizeof(fek), NULL,
                 0, iv, TEE_AES_BLOCK_SIZE);
    if (res != TEE_SUCCESS)
        goto exit;
    return 0;

exit:
    crypto_cipher_free_ctx(*ctx);
    return res;

}

static int tee_fs_crypt_run(uint8_t *buffer, size_t size,
                  TEE_OperationMode mode,
                  bool last, void **ctx)
{
    int res;
    uint8_t *out;

    out = malloc(size);

    if (!out) {
        ZF_LOGE("ERROR: out of memory");
        return -ENOMEM;
    }

    res = crypto_cipher_update(*ctx, mode, last, buffer, size, out);
    if (!res) {
        memcpy(buffer, out, size);
    } else {
        ZF_LOGE("ERROR: cipher update: %d", res);
    }

    free(out);

    return res;
}

static void tee_fs_crypt_close(void **ctx)
{
    if (!ctx || !*ctx) {
        return;
    }

    crypto_cipher_final(*ctx);
    crypto_cipher_free_ctx(*ctx);
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

static int export_storage_init()
{
    int err = -1;

    /* Calculate hash over ramdisk */
    err = teeos_optee_calc_hash(optee_ramdisk->buffer,
                                optee_ramdisk->buffer_len,
                                (uint8_t *)optee_ramdisk->buffer_hash,
                                sizeof(optee_ramdisk->buffer_hash));
    if (err) {
        return err;
    }

    /* Init encryption */
    err = tee_fs_crypt_init(TEE_MODE_ENCRYPT, &fs_ctx, NULL);
    if (err) {
        return err;
    }

    /* Read counter from NVM and increase it */
    err = read_counter(FS_MONOTONIC, &optee_ramdisk->ref_count);
    if (err) {
        return err;
    }

    optee_ramdisk->ref_count++;
    err = write_counter(FS_MONOTONIC, optee_ramdisk->ref_count);
    if (err) {
        return err;
    }

    return 0;
}

static int export_storage_crypto(void *buf,
                                 uint32_t buf_len,
                                 bool first_block,
                                 bool last_block)
{
    uint8_t *crypto_buf = (uint8_t *)buf;
    uint32_t crypto_len = buf_len;

    int err = -1;

    if (first_block) {
        /* IV is located at the beginning of buffer, skip */
        crypto_buf = (uint8_t *)(buf + IV_SIZE);
        crypto_len = buf_len - IV_SIZE;
    }

    err = tee_fs_crypt_run(crypto_buf, (size_t)crypto_len, TEE_MODE_ENCRYPT, last_block, &fs_ctx);
    if (err)
        goto err_out;

    if (last_block) {
        tee_fs_crypt_close(&fs_ctx);
        fs_ctx = NULL;
        ramdisk_fs_reset_storage_counter();
    }

    return 0;

err_out:
    tee_fs_crypt_close(&fs_ctx);
    fs_ctx = NULL;
    memset(buf, 0, buf_len);
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

    bool first_block = false;
    bool last_block = false;

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

        first_block = true;
        ZF_LOGI("Export first block");
    }

    ramdisk_len = sizeof(struct rambd_ext_hdr) + optee_ramdisk->buffer_len;

    /* at minimum 1 byte returned */
    if (storage_offset >= ramdisk_len) {
        ZF_LOGE("ERROR: invalid offset: %d", storage_offset);
        return -ESPIPE;
    }

    if (ramdisk_len - storage_offset <= buf_len) {
        last_block = true;
        ZF_LOGI("Export last block");
    }

    if (first_block) {
        err = export_storage_init();
        if (err) {
            return err;
        }
    }

    copy_len = MIN(ramdisk_len - storage_offset, buf_len);

    memcpy(buf, (uint8_t *)optee_ramdisk + storage_offset, copy_len);

    err = export_storage_crypto(buf, copy_len, first_block, last_block);
    if (err)
        return err;

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
    uint64_t counter_value;

    uint8_t hash[TEE_SHA256_HASH_SIZE] = { 0 } ;

    if (ramdisk->magic != RAMBD_HDR_MAGIC_V01) {
        ZF_LOGE("ERROR: bad magic: %ld", ramdisk->magic);
        return -EIO;
    }

    /* verify ramdisk->ref_count with monotonic counter value*/
    err = read_counter(FS_MONOTONIC, &counter_value);
    if (err) {
        return err;
    }
    if(counter_value != ramdisk->ref_count) {
        ZF_LOGE("ERROR: monotonic counter mismatch");
        return -EACCES;
    }

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

static int import_storage_init(uint8_t *import_buf, uint32_t storage_len, void **optee_buf)
{
    int ret = -1;
    void* buf = NULL;

    ZF_LOGI("storage_len: %d", storage_len);

    buf = calloc(1, storage_len);
    if (!buf) {
        ZF_LOGE("ERROR: out of memory");
        return -ENOMEM;
    }

    ret = tee_fs_crypt_init(TEE_MODE_DECRYPT, &fs_ctx, import_buf); /* IV is 16 first bytes */
    if (ret) {
        free(buf);
        ZF_LOGE("ERROR: crypto init: %d", ret);
        return ret;
    }

    optee_import.received = 0;
    optee_import.remaining = storage_len;

    *optee_buf = buf;

    return ret;
}

static int import_storage_crypto(uint32_t import_len, uint32_t crypto_pos,
                                 bool first_block, bool last_block)
{
    uint8_t *source = optee_import.buf + crypto_pos;
    uint32_t crypto_len = import_len;

    if (first_block) {
        /* Skip IV at the beginning of import buffer */
        source = optee_import.buf + IV_SIZE;
        crypto_len = import_len - IV_SIZE;
    }

    return tee_fs_crypt_run(source, (size_t)crypto_len, TEE_MODE_DECRYPT, last_block, &fs_ctx);
}

int teeos_optee_import_storage(uint8_t *import, uint32_t import_len,
                                uint32_t storage_len)
{
    int ret = -1;

    bool first_block = false;
    bool last_block = false;

    if (optee_ramdisk) {
        ZF_LOGI("ERROR: ramdisk already initialized");
        return -EACCES;
    }

    if (!import) {
        ZF_LOGI("ERROR: invalid parameter");
        return -EINVAL;
    }

    /* allocate buffer for importing storage */
    if (!optee_import.buf) {
        /* function allocates optee_import.buf and fs_ctx */
        ret = import_storage_init(import, storage_len, &optee_import.buf);
        if (ret) {
            return ret;
        }
    }

    if (import_len > optee_import.remaining) {
        ZF_LOGE("ERROR: corrupted import: %d / %d",
            import_len, optee_import.remaining);
        ret = -EFAULT;
        goto err_out;
    }

    if (optee_import.received == 0) {
        first_block = true;
        ZF_LOGI("Import first block");
    }

    if (optee_import.remaining - import_len == 0) {
        last_block = true;
        ZF_LOGI("Received complete storage: %d", optee_import.received + import_len);
    }

    memcpy(optee_import.buf + optee_import.received, import, import_len);

    ret = import_storage_crypto(import_len, optee_import.received,
                                first_block, last_block);
    if (ret) {
        goto err_out;
    }

    optee_import.remaining -= import_len;
    optee_import.received += import_len;

    if (last_block) {
        tee_fs_crypt_close(&fs_ctx);
        fs_ctx = NULL;

        ret = teeos_optee_import_storage_final(optee_import.buf, optee_import.received);
        if (ret) {
            goto err_out;
        }
        optee_ramdisk = optee_import.buf;
    }

    return 0;

err_out:
    tee_fs_crypt_close(&fs_ctx);
    fs_ctx = NULL;
    free(optee_import.buf);
    optee_import.buf = NULL;

    return ret;
}
