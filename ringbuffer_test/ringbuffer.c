#include <stdint.h>
#include "ringbuffer.h"
#include "sel4_circ.h"

static int writer_lock = 0;
static int reader_lock = 0;

int write_wrapper(struct tee_comm_ch *ch, int32_t data_len, const char *data_in)
{
    return sel4_write_to_circ(ch, data_len, data_in, &writer_lock);
}

int read_wrapper(struct tee_comm_ch *ch, int32_t out_len, char *out_buf, int32_t *read_len)
{
    return sel4_read_from_circ(ch, out_len, out_buf, read_len, &reader_lock);
}
