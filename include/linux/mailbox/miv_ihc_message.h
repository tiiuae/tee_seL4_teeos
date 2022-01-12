// SPDX-License-Identifier: GPL-2.0
/*
 * Mi-V Inter-hart communication (IHC) message
 *
 *Copyright (c) 2021 Microchip Technology Inc. All rights reserved.
 */

#ifndef _LINUX_MIV_IHC_H_
#define _LINUX_MIV_IHC_H_

#include <stdint.h>

/* Data structure for data-transfer protocol */
#define IHC_MAX_MESSAGE_SIZE 4U

struct miv_ihc_msg {
	uint32_t msg[IHC_MAX_MESSAGE_SIZE];
};

/* from: linux/drivers/mailbox/mailbox-miv-ihc.c */
enum {
	IHC_MP_IRQ = 0x0,
	IHC_ACK_IRQ = 0x1,
};

struct ihc_sbi_msg {
	uint8_t irq_type;
	struct miv_ihc_msg ihc_msg;
};

#endif /* _LINUX_MIV_IHC_H_ */