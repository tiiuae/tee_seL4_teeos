
/*
 * Copyright 2022, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <sel4/types.h>


int generate_key_pair(struct ree_tee_key_info *key_req, struct ree_tee_key_data_storage *payload, uint32_t max_size);
int extract_public_key(uint8_t *key_data, uint32_t key_data_length, uint8_t *guid,  uint32_t clientid, struct ree_tee_key_info *keyinfo, uint8_t *key, uint32_t max_size);
int teeos_init_crypto(void);