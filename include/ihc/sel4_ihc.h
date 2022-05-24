/*
 * Copyright 2022, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _SEL4_IHC_H_
#define _SEL4_IHC_H_

#include <stdint.h>

#include "linux/mailbox/miv_ihc_message.h"

int sel4_ihc_init(void *ihc_reg_base);
void sel4_ihc_reg_print();

int sel4_ihc_setup_ch_to_ree();
int sel4_ihc_ree_rx(uint32_t *irq_type, struct miv_ihc_msg *ihc_msg);
void sel4_ihc_ree_tx(struct miv_ihc_msg *ihc_msg);

#endif /* _SEL4_IHC_H_ */