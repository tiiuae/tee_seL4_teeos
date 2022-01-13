#ifndef _RINGBUFFER_H
#define _RINGBUFFER_H

#include "stdint.h"
#include "teeos_common.h"

int write_wrapper(struct tee_comm_ch *ch, int32_t data_len, const char *data_in);
int read_wrapper(struct tee_comm_ch *ch, int32_t out_len, char *out_buf, int32_t *read_len);

#endif /* _RINGBUFFER_H */