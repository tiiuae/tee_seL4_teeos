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


extern seL4_CPtr ipc_root_ep;
extern seL4_CPtr ipc_app_ep1;
extern void *app_shared_memory;



static struct ree_tee_key_data_storage* decrypt_key_data(uint8_t *key_data, uint32_t length, uint8_t *guid )
{
    guid = guid;
    length = length;
    return (struct ree_tee_key_data_storage *)key_data;
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
            nonce_service(key_req->guid);

            /* Use hard coded key for now */
            payload->key_info.pubkey_length = sizeof(public_key_pem);
            payload->key_info.privkey_length = sizeof(cert_pem);

            payload->storage_size = sizeof(struct ree_tee_key_data_storage)
            + payload->key_info.privkey_length
            + payload->key_info.pubkey_length;

            if (payload->storage_size > max_size) {
                return -ENOMEM;
            }

            ZF_LOGI("pub key Length = %u...key pair name %s", payload->key_info.pubkey_length, key_req->name);
            memcpy(&payload->keys[0], public_key_pem, sizeof(public_key_pem));
            strcpy(payload->key_info.name, key_req->name);

            ZF_LOGI("Private key Length = %u...", payload->key_info.privkey_length);
            memcpy(&payload->keys[payload->key_info.pubkey_length], cert_pem, payload->key_info.privkey_length);
            payload->key_info.key_nbits = key_req->key_nbits;

            /* copy uid */
            memcpy(payload->key_info.guid, key_req->guid, 32);

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

    if (clientid != payload->key_info.client_id)
        return -EINVAL;

    if (sizeof(struct ree_tee_key_data_storage) + payload->key_info.pubkey_length > max_size)
        return -ENOMEM;

    /* extract public key and key info*/
    ZF_LOGI("Public key length = %d Name %s", payload->key_info.pubkey_length, payload->key_info.name);
    memcpy(keyinfo, &payload->key_info, sizeof(struct ree_tee_key_info));
    keyinfo->privkey_length = 0;
    memcpy(&key[0], &payload->keys[0], payload->key_info.pubkey_length);

    return 0;
}
