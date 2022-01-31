/*
 * Copyright 2022, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

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

extern seL4_CPtr ipc_root_ep;
extern seL4_CPtr ipc_app_ep1;
extern void *app_shared_memory;

#define RSA_GUID_INDEX  0
#define KEY_BUF_SIZE    2048

#define  PK_PUBLIC      0x0000
   /* Refers to the private key */
#define PK_PRIVATE      0x0001

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
    guid = guid;
    length = length;
    return (struct ree_tee_key_data_storage *)key_data;
}

static int generate_guid(int index, uint8_t *guid)
{
    /* Use fixed challenge */
    uint8_t challenge[] = {0x49, 0x59, 0x48, 0x48, 0x50, 0x54, 0x42, 0x36, 0x6a, 0x61, 0x58, 0x71,
    0x52, 0x33, 0x57, 0x5a};

    int err = puf_emulation_service(challenge, index, guid);

    return err;
}


int generate_key_pair(struct ree_tee_key_info *key_req, struct ree_tee_key_data_storage *payload, uint32_t max_size)
{
    int err = -1;

    ZF_LOGI("Generate keypair file, format = %d", key_req->format);
    switch (key_req->format)
    {
        case KEY_RSA:
        {
           /* generate Guid from system controller*/
            err = generate_guid(RSA_GUID_INDEX, key_req->guid);
            if (err)
                return err;

            /* Copy keyinfo fields from req */
            memcpy(&payload->key_info, key_req, sizeof(struct ree_tee_key_info));

            err = generate_rsa_keypair(payload->key_info.key_nbits, &payload->keys[0], NULL, &payload->key_info.pubkey_length, &payload->key_info.privkey_length);
            if (err)
                return err;

            payload->storage_size = sizeof(struct ree_tee_key_data_storage)
            + payload->key_info.privkey_length
            + payload->key_info.pubkey_length;

            if (payload->storage_size > max_size) {
                return -ENOMEM;
            }

            ZF_LOGI("pub key Length = %u...key pair name %s", payload->key_info.pubkey_length, key_req->name);
            strcpy(payload->key_info.name, key_req->name);

            ZF_LOGI("Private key Length = %u...", payload->key_info.privkey_length);
            payload->key_info.key_nbits = key_req->key_nbits;

            /*Update length to request struct*/
            key_req->pubkey_length = payload->key_info.pubkey_length;
            key_req->privkey_length = payload->key_info.privkey_length;

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
        return -ENXIO;
    }

    if (sizeof(struct ree_tee_key_data_storage) + payload->key_info.pubkey_length > max_size)
        return -ENOMEM;

    /* extract public key and key info*/
    ZF_LOGI("Public key length = %d Name %s", payload->key_info.pubkey_length, payload->key_info.name);
    memcpy(keyinfo, &payload->key_info, sizeof(struct ree_tee_key_info));
    keyinfo->privkey_length = 0;
    memcpy(&key[0], &payload->keys[0], payload->key_info.pubkey_length);

    return 0;
}
