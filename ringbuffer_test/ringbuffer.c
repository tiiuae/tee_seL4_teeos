#include <stdint.h>
#include "ringbuffer.h"

static int writer_lock = 0;
static int reader_lock = 0;

int write_wrapper(struct circ_ctx *circ, int32_t data_len, const char *data_in)
{
    return sel4_write_to_circ(circ, data_len, data_in, &writer_lock);
}

int read_wrapper(struct circ_ctx *circ, int32_t out_len, char *out_buf, int32_t *read_len)
{
    return sel4_read_from_circ(circ, out_len, out_buf, read_len, &reader_lock);
}
