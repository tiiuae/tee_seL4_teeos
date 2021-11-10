#ifndef _RINGBUFFER_H
#define _RINGBUFFER_H

#include "stdint.h"
#include <linux/circ_buf.h>

struct tee_comm_ctrl {
	uint32_t ree_magic;
	uint32_t tee_magic;
	int32_t head;
	int32_t tail;
};

struct tee_comm_ch {
	struct tee_comm_ctrl *ctrl;
	int32_t buf_len;
	char *buf;
};

int write_wrapper(struct tee_comm_ch *ch, int32_t data_len, const char *data_in);
int read_wrapper(struct tee_comm_ch *ch, int32_t out_len, char *out_buf, int32_t *read_len);

#endif /* _RINGBUFFER_H */