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


static  struct ree_tee_key_data_storage  *active_key;

static void *optee_ramdisk_buf = NULL;
static uint32_t optee_ramdisk_buf_len = 0;

static void *partial_import = NULL;
static uint32_t partial_import_len = 0;

static int generate_ecc_keypair(int size,
                                 uint32_t keytype,
                                 uint8_t *pubkey,
                                 uint8_t *privkey,
                                 size_t *pubkey_l,  /* length fields are in/out, buffer size as input */
                                 size_t *privkey_l)
{

    int ret;
    static struct ecc_keypair key = {0};

    ret = crypto_acipher_alloc_ecc_keypair(&key, keytype, size);
    if (ret) {
        ZF_LOGI("Key allocation failed %d", ret);
        return ret;
    }

    ret = crypto_acipher_gen_ecc_key(&key, size);
    if (ret) {
        ZF_LOGI("Key generation failed %d", ret);
        goto exit;
    }

    ret = ecc_export_keys(&key, privkey, privkey_l, pubkey, pubkey_l);
    if (ret)
    {
        ZF_LOGI("export failed %d\n", ret);
    }

exit:
    ecc_free_keypair(&key);
    return ret;

}


static int generate_rsa_keypair(int size, uint8_t *pubkey, uint8_t *privkey, size_t *pubkey_l, size_t *privkey_l)
{
    static struct rsa_keypair key = {0};

    int r;
    uint32_t e;
    size_t length;

    r = crypto_acipher_alloc_rsa_keypair(&key, size);

    if (r)
    {
        ZF_LOGI("Key allocation failed %d\n", r);
        goto exit;
    }

    e = htobe32(65537);
    crypto_bignum_bin2bn((const uint8_t *)&e, sizeof(e), key.e);
    ZF_LOGI("generate keys");

    r = crypto_acipher_gen_rsa_key(&key, size);
    if (r != TEE_SUCCESS) {
        ZF_LOGI("rsa creation failed %d\n", r);
    }

    length = KEY_BUF_SIZE;

    r = crypto_acipher_extract_key(&key, privkey, &length, PK_PRIVATE );
    if (r != TEE_SUCCESS) {
        ZF_LOGI("rsa private key extract failed %d\n", r);
    }
    *privkey_l = length;
    length = KEY_BUF_SIZE;
    r = crypto_acipher_extract_key(&key, pubkey , &length, (PK_PUBLIC | PK_STD));
    if (r != TEE_SUCCESS) {
        ZF_LOGI("rsa public key extract failed %d\n", r);
    }
    *pubkey_l = length;

    crypto_acipher_free_rsa_keypair(&key);

exit:
    return r;
}

static struct ree_tee_key_data_storage* decrypt_key_data(uint8_t *key_data, uint32_t length, UNUSED uint8_t *guid )
{
    int err;
    size_t data_length = length + (16 - length%16);

    void *data =  malloc(data_length);
    if (!data)
        return NULL;

    memset(data, 0, data_length);

    err = tee_fs_crypt_block(&uuid, data,
                key_data, length, 1, fek,TEE_MODE_DECRYPT);

    if (err)
    {
        ZF_LOGI("Data decrypt failed %d", err);
        free(data);
        return NULL;

    }

    return (struct ree_tee_key_data_storage *)data;
}

static int generate_guid(int index, uint8_t *guid)
{
    /* Use fixed challenge */
    uint8_t challenge[] = {0x49, 0x59, 0x48, 0x48, 0x50, 0x54, 0x42, 0x36, 0x6a, 0x61, 0x58, 0x71,
    0x52, 0x33, 0x57, 0x5a};

    int err = puf_emulation_service(challenge, index, guid);

    return err;
}

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

int generate_key_pair(struct ree_tee_key_info *key_req, struct ree_tee_key_data_storage *payload, uint32_t max_size)
{
    int err = -1;
    uint8_t *privkey = NULL;
    uint8_t *pubkey = NULL;
    static size_t privkey_length;
    static size_t pubkey_length;

    privkey = malloc(KEY_BUF_SIZE);
    if(!privkey) {
        return -ENOMEM;
    }
    pubkey = malloc(KEY_BUF_SIZE);
    if(!pubkey) {
        free(privkey);
        return -ENOMEM;
    }

    switch (key_req->format)
    {
        case KEY_RSA_CIPHERED:
        case KEY_RSA_PLAINTEXT:
        {

#ifdef PLAINTEXT_DATA
            /* Force encryption */
            key_req->format = KEY_RSA_PLAINTEXT;
#endif
            /* generate Guid from system controller*/
            err = generate_guid(RSA_GUID_INDEX, key_req->guid);
            if (err)
                goto exit;

            err = generate_rsa_keypair(key_req->key_nbits,
                                         pubkey,
                                         privkey,
                                         &pubkey_length,
                                         &privkey_length);
            if (err)
                goto exit;



            err = 0;
            break;
        }
        case KEY_ECC_KEYPAIR:
        case KEY_X25519_KEYPAIR:
        {
            pubkey_length = KEY_BUF_SIZE;
            privkey_length = KEY_BUF_SIZE;

            if (key_req->format == KEY_ECC_KEYPAIR) {
                err = generate_guid(ECC_GUID_INDEX, key_req->guid);
                if (err)
                    goto exit;

                uint32_t keytype = TEE_TYPE_ECDSA_KEYPAIR;
                ZF_LOGI("Note: Keytype = TEE_TYPE_ECDSA %d", key_req->key_nbits);
                err = generate_ecc_keypair(key_req->key_nbits,
                                        keytype,
                                        pubkey,
                                        privkey,
                                        &pubkey_length,
                                        &privkey_length);
            } else {
                err = generate_guid(X25519_GUID_INDEX, key_req->guid);
                if (err)
                    goto exit;

                bool x509_format = false;
                if (key_req->key_nbits) {
                    x509_format = true;
                }
                err = generate_x25519_keypair(pubkey,
                                        privkey,
                                        &pubkey_length,
                                        &privkey_length,
                                        x509_format);
            }
            if (err) {
                ZF_LOGI("X25519 Key generation failed %d", err);
                goto exit;
            }

        }
        break;
        default:
            ZF_LOGI("Invalid KEY format %d", key_req->format);
            err = -EINVAL;
    }

    uint32_t storage_size = (uint32_t)(privkey_length + pubkey_length) + sizeof(struct ree_tee_key_data_storage);
    /* Round up storage size */
    storage_size = storage_size + (16 - storage_size%16);

    if (storage_size > max_size) {
        err = -ENOMEM;
        goto exit;
    }

    /*Update length to request struct*/
    key_req->pubkey_length = (uint32_t)pubkey_length;
    key_req->privkey_length = (uint32_t)privkey_length;
    key_req->storage_size = storage_size;

    /* Pack keys to the payload | public key | private key | */
    memcpy(&payload->keys[0], pubkey, pubkey_length);
    memcpy(&payload->keys[pubkey_length], privkey, privkey_length);

    /* Copy keyinfo fields from req */
    memcpy(&payload->key_info, key_req, sizeof(struct ree_tee_key_info));

    ZF_LOGI("pub key Length = %u...key pair name %s", payload->key_info.pubkey_length, key_req->name);
    ZF_LOGI("Private key Length = %u...", payload->key_info.privkey_length);

    if(key_req->format == KEY_RSA_CIPHERED)
    {
        uint8_t *tmp;
        tmp = malloc(4096);
        memset(tmp, 0,4096);
        if (!tmp)
        {
            err = -ENOMEM;
            goto exit;
        }
        ZF_LOGI("Encrypt data, size = %u", storage_size);

        err = tee_fs_crypt_block(&uuid, tmp,
                (uint8_t*)payload, storage_size,
                1, fek,
                TEE_MODE_ENCRYPT);

        ZF_LOGI("Encrypt: tee_fs_crypt_block = %d\n", err);

        /* Copy encrypted data */
        memcpy((void*)payload, tmp, storage_size);
        free(tmp);
    }


exit:
    /* We can now free temporary buffers */
    free(privkey);
    free(pubkey);
    return err;
}


int extract_public_key(struct key_data_blob *key_data, uint32_t key_data_length, struct ree_tee_key_info *keyinfo, uint8_t *key, uint32_t max_size)
{

    /* plaintext payload */
    if(key_data->key_data_info.format == KEY_RSA_PLAINTEXT)
    {
        memcpy(keyinfo, &key_data->key_data_info, sizeof(struct ree_tee_key_info));
        memcpy(&key[0], &key_data->key_data.keys[0], key_data->key_data.key_info.pubkey_length);
        return 0;
    }

    /*Decrypt payload*/
    struct ree_tee_key_data_storage *payload = decrypt_key_data((uint8_t*)&key_data->key_data, key_data_length, key_data->key_data_info.guid );


    if (!payload)
        return -EINVAL;

    /* Check Client id*/

    if (key_data->key_data_info.client_id != payload->key_info.client_id) {
        ZF_LOGE("ERROR clientid mismatch: %d (%d)", payload->key_info.client_id, key_data->key_data_info.client_id);
        free(payload);
        return -ENXIO;
    }

    if (sizeof(struct ree_tee_key_data_storage) + payload->key_info.pubkey_length > max_size)
    {
        free(payload);
        return -ENOMEM;
    }
    /* extract public key and key info*/
    ZF_LOGI("Public key length = %d Name %s", payload->key_info.pubkey_length, payload->key_info.name);
    memcpy(keyinfo, &payload->key_info, sizeof(struct ree_tee_key_info));
    keyinfo->privkey_length = 0;
    memcpy(&key[0], &payload->keys[0], payload->key_info.pubkey_length);

    /* Free payload */
    free(payload);
    return 0;
}

int import_key_blob(struct key_data_blob *key_data)
{
    uint32_t keytype = key_data->key_data_info.format;
    struct ree_tee_key_data_storage *plain_key_data;

    switch (keytype)
    {
    case KEY_RSA_CIPHERED:
        plain_key_data = decrypt_key_data((uint8_t*)&key_data->key_data, key_data->key_data_info.storage_size, key_data->key_data_info.guid);
        if (!plain_key_data)
            return -EINVAL;
        break;

    case KEY_RSA_PLAINTEXT:
        plain_key_data = malloc(key_data->key_data_info.storage_size);
        if (!plain_key_data)
            return -ENOMEM;
        memcpy(plain_key_data, &key_data->key_data, key_data->key_data_info.storage_size);
        break;
    default:
        ZF_LOGI("Unsupported keytype %u", keytype);
        return -EINVAL;
        break;
    }

    /* Check that keyblob is valid */

    /* check that guid match*/

    if (memcmp(plain_key_data->key_info.guid, key_data->key_data_info.guid, 32))
    {
        free(plain_key_data);
        return -EINVAL;
    }
    /* free previous key */
    free(active_key);

    active_key = plain_key_data;

    return 0;

}

void destroy_imported_key(void)
{
    free(active_key);
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