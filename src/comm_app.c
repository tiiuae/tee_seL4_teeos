/*
 * Copyright 2021, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <teeos/gen_config.h>

#include <regex.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>

#include <sel4runtime.h>
#include <sel4platsupport/platsupport.h>
#include <sel4utils/process.h>

#include <teeos_common.h>

#include <utils/fence.h>
#include <utils/zf_log.h>

#include <platsupport/sync/spinlock.h>
#include <utils/arith.h>
#include <linux/circ_buf.h>

seL4_CPtr ipc_root_ep = 0;

struct comm_ch {
    struct tee_comm_ch ree2tee;
    struct tee_comm_ch tee2ree;
};

static struct comm_ch comm = {0};

static sync_spinlock_t reader_lock;
static sync_spinlock_t writer_lock;

/* Linux code compatibility defines. Used in CIRC functions to keep
 * the source code same as in Linux driver.
 */
#define spin_lock(lock)                 sync_spinlock_lock(lock)
#define spin_unlock(lock)               sync_spinlock_unlock(lock)

#define READ_ONCE(source)               __atomic_load_n(&source, __ATOMIC_RELAXED)
#define smp_store_release(dest, val)    __atomic_store_n(dest, val, __ATOMIC_RELEASE)
#define smp_load_acquire(source)        __atomic_load_n(source, __ATOMIC_ACQUIRE)

#define min(a,b)    MIN(a,b)
/***************************************************/

static char *ree_msg_buf = NULL;

static int setup_comm_ch()
{
    seL4_Word sender_badge = 0;
    seL4_MessageInfo_t msg_info = { 0 };

    struct ipc_msg_ch_addr ch_addr = { 0 };
    seL4_Word *msg_data = (seL4_Word *)&ch_addr;

    struct tee_comm_ctrl *ch_ctrl = 0;

    ZF_LOGI("Waiting channel setup..");
    msg_info = seL4_Recv(ipc_root_ep, &sender_badge);

    seL4_Word msg_len = seL4_MessageInfo_get_length(msg_info);
    if (msg_len != IPC_CMD_WORDS(ch_addr)) {
        ZF_LOGF("ipc msg_len: %ld", msg_len);
        return -EINVAL;
    }

    for (seL4_Word i = 0; i < msg_len; i++) {
        msg_data[i] = seL4_GetMR(i);
    }

    if (ch_addr.cmd_id != IPC_CMD_CH_ADDR) {
        ZF_LOGF("ipc cmd_id: %p", (void *)ch_addr.cmd_id);
        return -EPERM;
    }

    if (ch_addr.ctrl_len < (sizeof(struct tee_comm_ctrl) * 2)) {
        ZF_LOGF("ctrl len: %ld", ch_addr.ctrl_len);
        return -ENOBUFS;
    }

    ch_ctrl = (struct tee_comm_ctrl *)ch_addr.ctrl;

    comm.ree2tee.ctrl = &ch_ctrl[COMM_CH_REE2TEE];
    comm.ree2tee.buf_len = ch_addr.ree2tee_len;
    comm.ree2tee.buf = (char *)ch_addr.ree2tee;

    comm.tee2ree.ctrl = &ch_ctrl[COMM_CH_TEE2REE];
    comm.tee2ree.buf_len = ch_addr.tee2ree_len;
    comm.tee2ree.buf = (char *)ch_addr.tee2ree;

    /* writer initializes channel */
    memset(comm.tee2ree.buf, 0x0, comm.tee2ree.buf_len);

    comm.tee2ree.ctrl->head = 0;
    comm.tee2ree.ctrl->tail = 0;

    /* Magic inidicates channel setup is ready. Compiler fence ensures
     * magic writing happens after init */
    COMPILER_MEMORY_RELEASE();
    comm.tee2ree.ctrl->tee_magic = COMM_MAGIC_TEE;
    comm.ree2tee.ctrl->tee_magic = COMM_MAGIC_TEE;

    ZF_LOGI("ch: ree2tee.ctrl [%p], buf [%p]", comm.ree2tee.ctrl,
            comm.ree2tee.buf);

    ZF_LOGI("ch: tee2ree.ctrl [%p], buf [%p]", comm.tee2ree.ctrl,
            comm.tee2ree.buf);

    return 0;
}

static int wait_ree_setup()
{
    uint32_t tee2ree_magic = comm.ree2tee.ctrl->ree_magic;
    uint32_t ree2tee_magic = comm.tee2ree.ctrl->ree_magic;

    ZF_LOGI("waiting REE magic...");
    /* wait until REE writes magic to both channels */
    while (tee2ree_magic != COMM_MAGIC_REE || tee2ree_magic != ree2tee_magic) {
        /* atomic load to prevent compiler optimization with
           while loop comparison */
        tee2ree_magic =
            __atomic_load_n(&comm.tee2ree.ctrl->ree_magic, __ATOMIC_RELAXED);
        ree2tee_magic =
            __atomic_load_n(&comm.ree2tee.ctrl->ree_magic, __ATOMIC_RELAXED);

        seL4_Yield();
    }

    ZF_LOGI("REE comm ready");

    return 0;
}

/*
 * Design copied from producer example: linux/Documentation/core-api/circular-buffers.rst
 */
static int write_to_circ(struct tee_comm_ch *circ, int32_t data_len,
                         const char *data_in)
{
    int ret = -ENOSPC;
    int32_t head = 0;
    int32_t tail = 0;
    int32_t buf_end = 0;
    int32_t write_ph1 = 0;
    int32_t wrap = 0;

    spin_lock(&writer_lock);

    head = circ->ctrl->head;

    /* The spin_unlock() and next spin_lock() provide needed ordering. */
    tail = READ_ONCE(circ->ctrl->tail);

    /* Shrink consecutive writes to the buffer end */
    buf_end = CIRC_SPACE_TO_END(head, tail, circ->buf_len);
    write_ph1 = min(buf_end, data_len);

    /* Remaining data if wrap needed, otherwise zero */
    wrap = data_len - write_ph1;

    if (CIRC_SPACE(head, tail, circ->buf_len) >= data_len) {
        memcpy(&circ->buf[head], data_in, write_ph1);

        /* Head will be automatically rolled back to the beginning of the buffer */
        head = (head + write_ph1) & (circ->buf_len - 1);

        if (wrap) {
            memcpy(&circ->buf[head], &data_in[write_ph1], wrap);
            head = (head + wrap) & (circ->buf_len - 1);
        }

        /* update the head after buffer write */
        smp_store_release(&circ->ctrl->head, head);

        /* TODO: wakeup reader */
        ret = 0;
    }

    spin_unlock(&writer_lock);

    return ret;
}

/*
 * Design copied from consumer example: linux/Documentation/core-api/circular-buffers.rst
 */
static int read_from_circ(struct tee_comm_ch *circ, int32_t out_len,
                          char *out_buf, int32_t *read_len)
{
    int ret = -ENODATA;
    int32_t head = 0;
    int32_t tail = 0;
    int32_t available = 0;
    int32_t buf_end = 0;
    int32_t read_ph1 = 0;
    int32_t wrap = 0;

    spin_lock(&reader_lock);

    /* Read index before reading contents at that index. */
    head = smp_load_acquire(&circ->ctrl->head);
    tail = circ->ctrl->tail;

    /* Shrink read length to output buffer size */
    available = min(out_len, CIRC_CNT(head, tail, circ->buf_len));

    /* Shrink consecutive reads to the buffer end */
    buf_end = CIRC_CNT_TO_END(head, tail, circ->buf_len);
    read_ph1 = min(available, buf_end);

    /* Remaining data if wrap needed, otherwise zero */
    wrap = available - read_ph1;

    *read_len = 0;

    if (available >= 1) {
        memcpy(out_buf, &circ->buf[tail], read_ph1);
        tail = (tail + read_ph1) & (circ->buf_len - 1);

        *read_len = read_ph1;

        if (wrap) {
            memcpy(&out_buf[read_ph1], &circ->buf[tail], wrap);
            tail = (tail + wrap) & (circ->buf_len - 1);
            *read_len += wrap;
        }

        /* Finish reading descriptor before incrementing tail. */
        smp_store_release(&circ->ctrl->tail, tail);

        ret = 0;
    }

    spin_unlock(&reader_lock);

    return ret;
}

static int handle_ree_msg(int32_t recv)
{
    ZF_LOGI("handle_ree_msg: %d", recv);

    while (write_to_circ(&comm.tee2ree, recv, ree_msg_buf)) {
        seL4_Yield();
    }

    return 0;
}

static int wait_ree_msg()
{
    int res = -1;
    int32_t recv = 0;

    /* Spinlocks for buffer handling */
    sync_spinlock_init(&reader_lock);
    sync_spinlock_init(&writer_lock);

    /* Intermediate buffer for storing REE msg */
    ree_msg_buf = malloc(comm.ree2tee.buf_len);
    if (!ree_msg_buf) {
        ZF_LOGF("ree_recv_buf == NULL");
        return -ENOMEM;
    }

    ZF_LOGI("waiting REE msg...");
    while (1) {
        seL4_Yield();

        res = read_from_circ(&comm.ree2tee, comm.ree2tee.buf_len, ree_msg_buf,
                             &recv);
        if (res || recv < 1) {
            continue;
        }

        res = handle_ree_msg(recv);
    }
    return 0;
}

int main(int argc, char **argv)
{
    int error = -1;

    ZF_LOGI("%s", CONFIG_TEE_COMM_APP_NAME);
    seL4_DebugNameThread(SEL4UTILS_TCB_SLOT, CONFIG_TEE_COMM_APP_NAME);

    if (argc != 1) {
        ZF_LOGF("Invalid arg count: %d", argc);
        return -EINVAL;
    }

    ipc_root_ep = (seL4_CPtr)atol(argv[0]);
    if (ipc_root_ep == 0) {
        ZF_LOGF("Invalid endpoint");
        return -EFAULT;
    }

    ZF_LOGI("ipc_root_ep: %p", (void *)ipc_root_ep);

    /* Wait shared memory config from rootserver and init tee2ree channel */
    error = setup_comm_ch(ipc_root_ep);
    if (error) {
        return error;
    }

    /* Wait linux to init ree2tee channel */
    error = wait_ree_setup();
    if (error) {
        return error;
    }

    error = wait_ree_msg();

    return error;
}