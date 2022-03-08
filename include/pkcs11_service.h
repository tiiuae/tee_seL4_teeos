/*
 * Copyright 2022, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#pragma once

#include "sel4_optee_serializer.h"


int sel4_init_pkcs11_session(void);
int sel4_execute_pkcs11_command(TEE_Param params[TEE_NUM_PARAMS], uint32_t paramstype, uint32_t cmd);
void sel4_close_pkcs11_session(void);

int test_pkcs11(void);


