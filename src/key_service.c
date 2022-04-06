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

static void *optee_ramdisk_buf = NULL;
static uint32_t optee_ramdisk_buf_len = 0;

static void *partial_import = NULL;
static uint32_t partial_import_len = 0;

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

    if (optee_ramdisk_buf) {
        ZF_LOGI("ramdisk already initialized");
        return 0;
    }

    /* create an empty ramdisk */
    ret = ramdisk_fs_init(NULL, 0, &optee_ramdisk_buf, &optee_ramdisk_buf_len);
    if (ret) {
        ZF_LOGE("ERROR: %d", ret);
        ret = -EIO;
    }

    return ret;
}
int teeos_reseed_fortuna_rng(void)
{
    return sys_reseed_fortuna_rng();
}

int teeos_optee_export_storage(uint32_t storage_offset,
                               uint32_t *storage_len,
                               void *buf,
                               uint32_t buf_len,
                               uint32_t *export_len)
{
    uint32_t copy_len = MIN(optee_ramdisk_buf_len - storage_offset, buf_len);

    if (!storage_len || !buf || !export_len) {
        ZF_LOGF("ERROR: invalid parameter");
        return -EINVAL;
    }

    if (!optee_ramdisk_buf) {
        ZF_LOGE("ERROR: ramdisk not created");
        return -EACCES;
    }

    /* at minimum 1 byte returned */
    if (storage_offset >= optee_ramdisk_buf_len) {
        ZF_LOGE("ERROR: invalid offset: %d", storage_offset);
        return -ESPIPE;
    }

    memcpy(buf, optee_ramdisk_buf + storage_offset, copy_len);

    *storage_len = optee_ramdisk_buf_len;
    *export_len = copy_len;

    ZF_LOGI("buff: %d, offset: %d, export: %d, storage: %d",
        buf_len, storage_offset, *export_len, *storage_len);

    return 0;
}

int teeos_optee_import_storage(uint8_t *import, uint32_t import_len,
                                uint32_t storage_len)
{
    int ret = -1;

    if (optee_ramdisk_buf) {
        ZF_LOGI("ERROR: ramdisk already initialized");
        return -EACCES;
    }

    /* allocate buffer for importing storage */
    if (!partial_import) {
        ZF_LOGI("storage_len: %d", storage_len);

        partial_import = calloc(1, storage_len);
        if (!partial_import) {
            ZF_LOGE("ERROR: out of memory");
            return -ENOMEM;
        }

        optee_ramdisk_buf_len = storage_len;
    }

    if (partial_import_len + import_len > optee_ramdisk_buf_len) {
        ZF_LOGE("ERROR: corrupted import: %d / %d / %d",
            partial_import_len, import_len, optee_ramdisk_buf_len);
        ret = -EFAULT;
        goto err_out;
    }

    memcpy(partial_import + partial_import_len, import, import_len);

    partial_import_len += import_len;

    ZF_LOGI("import: %d, pos: %d", import_len, partial_import_len);

    /* last import message, init ramdisk */
    if (partial_import_len == optee_ramdisk_buf_len) {
        ZF_LOGI("Received complete storage: %d", optee_ramdisk_buf_len);

        /* use imported storage data to create ramdisk */
        ret = ramdisk_fs_init(partial_import, partial_import_len, NULL, 0);
        if (ret) {
            ZF_LOGE("ERROR: %d", ret);
            ret = -EIO;
            goto err_out;
        }

        optee_ramdisk_buf = partial_import;
        optee_ramdisk_buf_len = partial_import_len;
    }

    return 0;

err_out:
    free(partial_import);
    partial_import = NULL;
    partial_import_len = 0;
    optee_ramdisk_buf_len = 0;

    return ret;
}