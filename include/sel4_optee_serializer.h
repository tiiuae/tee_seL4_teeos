/*
 * Copyright 2022, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _SEL4_OPTEE_SERIALIZER_H_
#define _SEL4_OPTEE_SERIALIZER_H_

#include <stdint.h>
#include "tee_api_types.h"

struct serialized_param {
    uint32_t param_type;
    uint32_t val_len;
    uint8_t value[0];
};

int sel4_optee_serialize(struct serialized_param **ser_param, uint32_t *ser_len, uint32_t ptypes, TEE_Param *tee_params);
int sel4_optee_deserialize(struct serialized_param *ser_param, uint32_t ser_len, uint32_t *ptypes, TEE_Param *tee_params);
void sel4_dealloc_memrefs(uint32_t ptypes, TEE_Param *tee_params);

#endif /* _SEL4_OPTEE_SERIALIZER_H_ */