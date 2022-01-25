#ifndef _RINGBUFFER_H
#define _RINGBUFFER_H

#include "stdint.h"
#include "teeos_common.h"
#include "sel4_circ.h"

int write_wrapper(struct circ_ctx *circ, int32_t data_len, const char *data_in);
int read_wrapper(struct circ_ctx *circ, int32_t out_len, char *out_buf, int32_t *read_len);

#endif /* _RINGBUFFER_H */