/*
 * Copyright 2022, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/* Local log level */
#define ZF_LOG_LEVEL ZF_LOG_INFO
#define PLAINTEXT_DATA

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

extern seL4_CPtr ipc_root_ep;
extern seL4_CPtr ipc_app_ep1;
extern void *app_shared_memory;

#define RSA_GUID_INDEX  0
#define KEY_BUF_SIZE    2048
#define FEK_SIZE        16u

#define  PK_PUBLIC      0x0000
   /* Refers to the private key */
#define PK_PRIVATE      0x0001

static const TEE_UUID uuid = {
                    0x5f8b97df, 0x2d0d, 0x4ad2,
                    {0x98, 0xd2, 0x74, 0xf4, 0x38, 0x27, 0x98, 0xbb},
                };

static uint8_t fek[FEK_SIZE];

static int generate_rsa_keypair(int size, uint8_t *pubkey, uint8_t *privkey, uint32_t *pubkey_l, uint32_t *privkey_l)
{
    static struct rsa_keypair key = {0};

    int r;
    uint32_t e;
    size_t length;

    uint8_t *tmp_pub;
    uint8_t *tmp_prv;

    tmp_pub = malloc(KEY_BUF_SIZE);
    if(!tmp_pub)
    {
        r = -ENOMEM;
        goto exit;
    }
    tmp_prv = malloc(KEY_BUF_SIZE);
    if(!tmp_prv)
    {
        r = -ENOMEM;
        goto exit;
    }
    ZF_LOGI("allocate keys, key size = %d bits", size);
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


    ZF_LOGI("Extract keys");
    r = crypto_acipher_extract_key(&key, tmp_prv, &length, PK_PRIVATE );
    if (r != TEE_SUCCESS) {
        ZF_LOGI("rsa private key extract failed %d\n", r);
    }
    *privkey_l = length;
    length = KEY_BUF_SIZE;
    r = crypto_acipher_extract_key(&key, tmp_pub , &length, PK_PUBLIC );
    if (r != TEE_SUCCESS) {
        ZF_LOGI("rsa public key extract failed %d\n", r);
    }
    *pubkey_l = length;

    ZF_LOGI("public key = %u private key %u bytes, copy public key to byte array..", *pubkey_l , *privkey_l );
    memcpy(pubkey, &tmp_pub[0], *pubkey_l );
    privkey=&pubkey[*pubkey_l];
    memcpy(privkey, &tmp_prv[0], *privkey_l);

    ZF_LOGI("free keys");
    crypto_acipher_free_rsa_keypair(&key);

exit:
    free(tmp_pub);
    free(tmp_prv);

    return r;
}

static struct ree_tee_key_data_storage* decrypt_key_data(uint8_t *key_data, uint32_t length, uint8_t *guid )
{
    int err;
    size_t data_length = length + (16 - length%16);
    struct ree_tee_key_data_storage *chk = (struct ree_tee_key_data_storage*)key_data;

    void *data =  malloc(data_length);
    if (!data)
        return NULL;

    memset(data, 0, data_length);

    if (memcmp(guid, &chk->key_info.guid[0], 32) == 0)
    {
        ZF_LOGI("Plain textdata, encryption not needed");
        memcpy(data,key_data,length);
    }
    else
    {
        err = tee_fs_crypt_block(&uuid, data,
                    key_data, length, 1, fek,TEE_MODE_DECRYPT);

        if (err)
        {
            ZF_LOGI("Data decrypt failed %d", err);
            free(data);
            return NULL;

        }
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
    ZF_LOGI("Generate keypair file, format = %d", key_req->format);
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
                return err;

            memset(&payload->keys[0], 0, 4096);
            /* Copy keyinfo fields from req */
            memcpy(&payload->key_info, key_req, sizeof(struct ree_tee_key_info));

            err = generate_rsa_keypair(payload->key_info.key_nbits, &payload->keys[0], NULL, &payload->key_info.pubkey_length, &payload->key_info.privkey_length);
            if (err)
                return err;

            uint32_t keysize = payload->key_info.privkey_length
            + payload->key_info.pubkey_length;

            payload->key_info.storage_size = sizeof(struct ree_tee_key_data_storage)
            + keysize;

            /* Round up storage size */
            payload->key_info.storage_size = payload->key_info.storage_size + (16 - payload->key_info.storage_size%16);

            if (payload->key_info.storage_size > max_size) {
                return -ENOMEM;
            }

            ZF_LOGI("pub key Length = %u...key pair name %s", payload->key_info.pubkey_length, key_req->name);
            ZF_LOGI("Private key Length = %u...", payload->key_info.privkey_length);

            /*Update length to request struct*/
            key_req->pubkey_length = payload->key_info.pubkey_length;
            key_req->privkey_length = payload->key_info.privkey_length;
            key_req->storage_size = payload->key_info.storage_size;

            if(key_req->format == KEY_RSA_CIPHERED)
            {
                uint8_t *tmp;
                tmp = malloc(4096);
                memset(tmp, 0,4096);
                if (!tmp)
                {
                    err = -ENOMEM;
                    break;
                }
                ZF_LOGI("Encrypt data, size = %u", key_req->storage_size);

                err = tee_fs_crypt_block(&uuid, tmp,
                        (uint8_t*)payload, key_req->storage_size,
                        1, fek,
                        TEE_MODE_ENCRYPT);

                ZF_LOGI("Encrypt: tee_fs_crypt_block = %d\n", err);

                /* Copy encrypted data */
                memcpy((void*)payload, tmp, key_req->storage_size);
                free(tmp);
            }

            err = 0;
            break;
        }
        default:
            ZF_LOGI("Invalid KEY format %d", key_req->format);
            err = -EINVAL;
            break;
    }
    return err;
}


int extract_public_key(uint8_t *key_data, uint32_t key_data_length, uint8_t *guid,  uint32_t clientid, struct ree_tee_key_info *keyinfo, uint8_t *key, uint32_t max_size)
{
    /*Decrypt payload*/

    struct ree_tee_key_data_storage *payload = decrypt_key_data(key_data, key_data_length, guid );


    if (!payload)
        return -EINVAL;

    /* Check Client id*/

    if (clientid != payload->key_info.client_id) {
        ZF_LOGE("ERROR clientid mismatch: %d (%d)", payload->key_info.client_id, clientid);
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
