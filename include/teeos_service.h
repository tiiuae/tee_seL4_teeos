
/*
 * Copyright 2022, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <sel4/types.h>

int teeos_init_crypto(void);
int teeos_init_optee_storage(void);
int teeos_reseed_fortuna_rng(void);
int teeos_optee_export_storage(uint32_t storage_offset, uint32_t *storage_len, void *buf, uint32_t buf_len, uint32_t *export_len);
int teeos_optee_import_storage(uint8_t *import, uint32_t import_len, uint32_t storage_len);