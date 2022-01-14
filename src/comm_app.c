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
#include <ree_tee_msg.h>

#include <utils/fence.h>
#include <utils/zf_log.h>

#include <platsupport/sync/spinlock.h>
#include <utils/arith.h>
#include "sel4_circ.h"

#include "rpmsg_sel4.h"

seL4_CPtr ipc_root_ep = 0;
seL4_CPtr ipc_app_ep1 = 0;
void *app_shared_memory;

struct comm_ch {
    struct tee_comm_ch ree2tee;
    struct tee_comm_ch tee2ree;

    struct sel4_rpmsg_config rpmsg_conf;
};

static struct comm_ch comm = {0};

static sync_spinlock_t reader_lock;
static sync_spinlock_t writer_lock;

#define SET_REE_HDR(hdr, msg, stat, len) {  \
            hdr->msg_type = msg;            \
            hdr->status = stat;             \
            hdr->length = len;              \
        }

#define REE_HDR_LEN     sizeof(struct ree_tee_hdr)

static char *ree_msg_buf = NULL;

static int setup_comm_ch(void)
{
    int error = -1;

    /* IPC response */
    struct ipc_msg_ch_addr ipc_resp = { 0 };
    const uint32_t RESP_WORDS = IPC_CMD_WORDS(ipc_resp);
    seL4_Word *msg_data = (seL4_Word *)&ipc_resp;

    struct tee_comm_ctrl *ch_ctrl = 0;

    ZF_LOGI("seL4_Call: IPC_CMD_CH_ADDR_REQ");

    error = ipc_msg_call(IPC_CMD_CH_ADDR_REQ,
                         ipc_root_ep,
                         RESP_WORDS,
                         msg_data);

    if (error) {
        ZF_LOGF("error ipc_msg_call: %d", error);
        return error;
    }

    if (ipc_resp.cmd_id != IPC_CMD_CH_ADDR_RESP) {
        ZF_LOGF("ipc cmd_id: 0x%lx", ipc_resp.cmd_id);
        return -EPERM;
    }

    if (ipc_resp.ctrl_len < (sizeof(struct tee_comm_ctrl) * 2)) {
        ZF_LOGF("ctrl len: %ld", ipc_resp.ctrl_len);
        return -ENOBUFS;
    }
    app_shared_memory = (void *)ipc_resp.shared_memory;

    ch_ctrl = (struct tee_comm_ctrl *)ipc_resp.ctrl;

    comm.ree2tee.ctrl = &ch_ctrl[COMM_CH_REE2TEE];
    comm.ree2tee.buf_len = ipc_resp.ree2tee_len;
    comm.ree2tee.buf = (char *)ipc_resp.ree2tee;

    comm.tee2ree.ctrl = &ch_ctrl[COMM_CH_TEE2REE];
    comm.tee2ree.buf_len = ipc_resp.tee2ree_len;
    comm.tee2ree.buf = (char *)ipc_resp.tee2ree;

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

static int setup_ihc_buf(struct sel4_rpmsg_config *rpmsg_conf)
{
    int error = -1;

    /* IPC response */
    struct ipc_msg_ihc_buf ipc_resp = { 0 };
    const uint32_t RESP_WORDS = IPC_CMD_WORDS(ipc_resp);
    seL4_Word *msg_data = (seL4_Word *)&ipc_resp;

    ZF_LOGI("seL4_Call: IPC_CMD_RPMSG_CONF_REQ");

    error = ipc_msg_call(IPC_CMD_RPMSG_CONF_REQ,
                         ipc_root_ep,
                         RESP_WORDS,
                         msg_data);

    if (error) {
        return error;
    }

    if (ipc_resp.cmd_id != IPC_CMD_RPMSG_CONF_RESP) {
        ZF_LOGF("ipc cmd_id: 0x%lx", ipc_resp.cmd_id);
        return -EPERM;
    }

    rpmsg_conf->ihc_buf_pa = ipc_resp.ihc_buf_pa;
    rpmsg_conf->ihc_buf_va = (void*)ipc_resp.ihc_buf_va;
    rpmsg_conf->ihc_irq = ipc_resp.ihc_irq;
    rpmsg_conf->ihc_ntf = ipc_resp.ihc_ntf;
    rpmsg_conf->vring_va = (void*)ipc_resp.vring_va;
    rpmsg_conf->vring_pa = ipc_resp.vring_pa;

    ZF_LOGI("ihc_buf_pa [0x%lx]", rpmsg_conf->ihc_buf_pa);
    ZF_LOGI("ihc_buf_va [%p]", rpmsg_conf->ihc_buf_va);
    ZF_LOGI("ihc_irq    [0x%lx]", rpmsg_conf->ihc_irq);
    ZF_LOGI("ihc_ntf    [0x%lx]", rpmsg_conf->ihc_ntf);
    ZF_LOGI("vring_va   [0%p]", rpmsg_conf->vring_va);
    ZF_LOGI("vring_pa   [0x%lx]", rpmsg_conf->vring_pa);

    return 0;
}

static int setup_app_ep(void)
{
    int error = -1;

    /* IPC response */
    struct ipc_msg_app_ep ipc_resp = { 0 };
    seL4_Word *msg_data = (seL4_Word *)&ipc_resp;

    ZF_LOGI("seL4_Call: IPC_CMD_APP_EP_REQ");

    error = ipc_msg_call(IPC_CMD_APP_EP_REQ,
                         ipc_root_ep,
                         IPC_CMD_WORDS(ipc_resp),
                         msg_data);

    if (error) {
        ZF_LOGF("error ipc_msg_call: %d", error);
        return error;
    }

    if (ipc_resp.cmd_id != IPC_CMD_APP_EP_RESP) {
        ZF_LOGF("ipc cmd_id: 0x%lx", ipc_resp.cmd_id);
        return -EPERM;
    }

    ipc_app_ep1 = ipc_resp.app_ep;

    ZF_LOGI("ipc_app_ep1: 0x%lx", ipc_app_ep1);

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


static int handle_ree_msg(int32_t recv)
{
    ZF_LOGI("handle_ree_msg: %d", recv);

    struct ree_tee_hdr *hdr = (struct ree_tee_hdr *)ree_msg_buf;

    seL4_MessageInfo_t msg_info = { 0 };
    seL4_Word msg_len = 0;
    seL4_Word msg_data = 0;

    switch (hdr->msg_type)
    {
        case REE_TEE_STATUS_REQ:
        {
            /* header only, no params for req */

            ZF_LOGI("Status Request from REE ..");
            SET_REE_HDR(hdr, REE_TEE_STATUS_RESP, TEE_OK, REE_HDR_LEN);
        }
        break;
        case REE_TEE_RNG_REQ:
        {
            struct ree_tee_rng_cmd *cmd = (struct ree_tee_rng_cmd *)ree_msg_buf;

            /* header only, no params for req */

            /*call to sys app*/
            ZF_LOGI("Send msg to sys app...");
            msg_info = seL4_MessageInfo_new(0, 0, 0, 1);

            seL4_SetMR(0, IPC_CMD_SYS_CTL_RNG_REQ);

            msg_info = seL4_Call(ipc_app_ep1, msg_info);

            ZF_LOGI("Sys app responce received...");
            msg_len = seL4_MessageInfo_get_length(msg_info);
            if (msg_len > 0) {
                msg_data = seL4_GetMR(0);
            }
            if (msg_data == IPC_CMD_SYS_CTL_RNG_RESP)
            {
                SET_REE_HDR(hdr, REE_TEE_RNG_RESP, TEE_OK,
                            sizeof(struct ree_tee_rng_cmd));

                /* copy random number from shared buffer*/
                memcpy(cmd->response, app_shared_memory, RNG_SIZE_IN_BYTES );
            }
            else
            {
                SET_REE_HDR(hdr, REE_TEE_RNG_RESP, TEE_IPC_CMD_ERR,
                            REE_HDR_LEN);
            }
        }
        break;
        case REE_TEE_SNVM_WRITE_REQ:
        {
            struct ree_tee_snvm_cmd *cmd = (struct ree_tee_snvm_cmd *)ree_msg_buf;

            if (recv != sizeof(struct ree_tee_snvm_cmd)) {

                ZF_LOGI("Invalid Message size");
                SET_REE_HDR(hdr, REE_TEE_SNVM_WRITE_RESP, TEE_INVALID_MSG_SIZE,
                            REE_HDR_LEN);
            } else {
                /* copy  message to shared buffer */
                memcpy(app_shared_memory, ree_msg_buf, sizeof(struct ree_tee_snvm_cmd));
                /* Sens msg to sys app */
                cmd =  (struct ree_tee_snvm_cmd *)app_shared_memory;
                ZF_LOGI("Send msg to sys app...");
                msg_info = seL4_MessageInfo_new(0, 0, 0, 5);

                seL4_SetMR(0, IPC_CMD_SYS_CTL_SNVM_WRITE_REQ);
                seL4_SetMR(1, (seL4_Word)cmd->page_number);
                seL4_SetMR(2, (seL4_Word)cmd->user_key);
                seL4_SetMR(3, (seL4_Word)cmd->data);
                seL4_SetMR(4, (seL4_Word)cmd->snvm_length);

                msg_info = seL4_Call(ipc_app_ep1, msg_info);

                ZF_LOGI("Sys app responce received...");
                msg_len = seL4_MessageInfo_get_length(msg_info);
                if (msg_len > 0) {
                    msg_data = seL4_GetMR(0);
                }
                if (msg_data == IPC_CMD_SYS_CTL_SNVM_WRITE_RESP) {
                    /* Return only ok status in header */
                    SET_REE_HDR(hdr, REE_TEE_SNVM_WRITE_RESP, TEE_OK,
                                REE_HDR_LEN);
                } else {
                    SET_REE_HDR(hdr, REE_TEE_SNVM_WRITE_RESP, TEE_IPC_CMD_ERR,
                                REE_HDR_LEN);
                }
            }
        }
        break;
        case REE_TEE_SNVM_READ_REQ:
        {
            struct ree_tee_snvm_cmd *cmd = (struct ree_tee_snvm_cmd *)ree_msg_buf;
            struct ree_tee_snvm_cmd *ipc = (struct ree_tee_snvm_cmd *)app_shared_memory;

            if (recv != sizeof(struct ree_tee_snvm_cmd)) {
                ZF_LOGI("Invalid Message size");
                SET_REE_HDR(hdr, REE_TEE_SNVM_READ_RESP, TEE_INVALID_MSG_SIZE,
                            REE_HDR_LEN);
            } else {
                /* copy  message to shared buffer */
                memcpy(app_shared_memory, ree_msg_buf, sizeof(struct ree_tee_snvm_cmd));
                /* req point to shared memory */
                ZF_LOGI("Send msg to sys app...");
                msg_info = seL4_MessageInfo_new(0, 0, 0, 5);

                seL4_SetMR(0, IPC_CMD_SYS_CTL_SNVM_READ_REQ);
                seL4_SetMR(1, (seL4_Word)ipc->page_number);
                seL4_SetMR(2, (seL4_Word)ipc->user_key);
                seL4_SetMR(3, (seL4_Word)ipc->data);
                seL4_SetMR(4, (seL4_Word)ipc->snvm_length);

                msg_info = seL4_Call(ipc_app_ep1, msg_info);

                ZF_LOGI("Sys app responce received...");
                msg_len = seL4_MessageInfo_get_length(msg_info);
                if (msg_len > 0) {
                    msg_data = seL4_GetMR(0);
                }
                if (msg_data == IPC_CMD_SYS_CTL_SNVM_READ_RESP) {
                    SET_REE_HDR(hdr, REE_TEE_SNVM_READ_RESP, TEE_OK,
                                sizeof(struct ree_tee_snvm_cmd));

                    /* Copy read data from IPC msg to REE message */
                    memcpy(cmd->data, ipc->data, sizeof(ipc->data));
                    /* Clear key from REE message before returning */
                    memset(cmd->user_key, 0xFF, sizeof(cmd->user_key));
                } else {
                    SET_REE_HDR(hdr, REE_TEE_SNVM_READ_RESP, TEE_IPC_CMD_ERR,
                                REE_HDR_LEN);
                }
            }
        }
        break;
        case REE_TEE_DEVICEID_REQ:
        {
            struct ree_tee_deviceid_cmd *cmd = (struct ree_tee_deviceid_cmd *)ree_msg_buf;

            /* header only, no params for req */

            /*call to sys app*/

            ZF_LOGI("Send msg to sys app...");
            msg_info = seL4_MessageInfo_new(0, 0, 0, 1);

            seL4_SetMR(0, IPC_CMD_SYS_CTL_DEVICEID_REQ);

            msg_info = seL4_Call(ipc_app_ep1, msg_info);

            ZF_LOGI("Sys app responce received...");
            msg_len = seL4_MessageInfo_get_length(msg_info);
            if (msg_len > 0) {
                msg_data = seL4_GetMR(0);
            }
            if (msg_data == IPC_CMD_SYS_CTL_DEVICEID_RESP)
            {
                SET_REE_HDR(hdr, REE_TEE_DEVICEID_RESP, TEE_OK,
                            sizeof(struct ree_tee_deviceid_cmd));

                /* copy device id from shared buffer*/
                memcpy(cmd->response, app_shared_memory, DEVICE_ID_LENGTH);
            }
            else
            {
                SET_REE_HDR(hdr, REE_TEE_DEVICEID_RESP, TEE_IPC_CMD_ERR,
                            REE_HDR_LEN);
            }
        }
        break;
        case REE_TEE_PUF_REQ:
        {
            /*
             * response struct @  shared ram
             */
            struct ree_tee_puf_cmd *cmd = (struct ree_tee_puf_cmd *)ree_msg_buf;
            struct ree_tee_puf_cmd *ipc = (struct ree_tee_puf_cmd *)app_shared_memory;

            if (recv != sizeof(struct ree_tee_puf_cmd)) {
                ZF_LOGI("Invalid Message size");
                SET_REE_HDR(hdr, REE_TEE_PUF_RESP, TEE_INVALID_MSG_SIZE,
                            REE_HDR_LEN);
            } else {
                /* Copy cmd to shared ram*/
                memcpy(app_shared_memory, ree_msg_buf, sizeof(struct ree_tee_puf_cmd));

                ZF_LOGI("Send msg to sys app...");
                msg_info = seL4_MessageInfo_new(0, 0, 0, 4);

                seL4_SetMR(0, IPC_CMD_SYS_CTL_PUF_REQ);
                seL4_SetMR(1, (seL4_Word)ipc->request);
                seL4_SetMR(2, (seL4_Word)ipc->opcode);
                seL4_SetMR(3, (seL4_Word)ipc->response);

                msg_info = seL4_Call(ipc_app_ep1, msg_info);

                ZF_LOGI("Sys app responce received...");
                msg_len = seL4_MessageInfo_get_length(msg_info);
                if (msg_len > 0) {
                    msg_data = seL4_GetMR(0);
                }

                if (msg_data == IPC_CMD_SYS_CTL_PUF_RESP)
                {
                    SET_REE_HDR(hdr, REE_TEE_PUF_RESP, TEE_OK,
                                sizeof(struct ree_tee_puf_cmd));

                    /* copy puf response from shared buffer*/
                    memcpy(cmd->response, ipc->response, sizeof(ipc->response));
                }
                else
                {
                    SET_REE_HDR(hdr, REE_TEE_PUF_RESP, TEE_IPC_CMD_ERR,
                                REE_HDR_LEN);
                }
            }
        }
        break;
        case REE_TEE_SIGN_REQ:
        {
            /*
             * request struct copied @ begin of shared ram
             */
            struct ree_tee_sign_cmd *cmd = (struct ree_tee_sign_cmd *)ree_msg_buf;
            struct ree_tee_sign_cmd *ipc = (struct ree_tee_sign_cmd *)app_shared_memory;

            if (recv != sizeof(struct ree_tee_sign_cmd)) {
                ZF_LOGI("Invalid Message size");
                SET_REE_HDR(hdr, REE_TEE_PUF_RESP, TEE_INVALID_MSG_SIZE,
                            REE_HDR_LEN);
            } else {
                /* Copy cmd to shared ram*/
                memcpy(app_shared_memory, ree_msg_buf, sizeof(struct ree_tee_sign_cmd));

                ZF_LOGI("Send msg to sys app...");
                msg_info = seL4_MessageInfo_new(0, 0, 0, 4);

                seL4_SetMR(0, IPC_CMD_SYS_CTL_SIGN_REQ);
                seL4_SetMR(1, (seL4_Word)ipc->hash);
                seL4_SetMR(2, (seL4_Word)ipc->format);
                seL4_SetMR(3, (seL4_Word)ipc->response);

                msg_info = seL4_Call(ipc_app_ep1, msg_info);

                ZF_LOGI("Sys app responce received...");
                msg_len = seL4_MessageInfo_get_length(msg_info);
                if (msg_len > 0) {
                    msg_data = seL4_GetMR(0);
                }

                if (msg_data == IPC_CMD_SYS_CTL_SIGN_RESP)
                {
                    SET_REE_HDR(hdr, REE_TEE_SIGN_RESP, TEE_OK,
                                sizeof(struct ree_tee_sign_cmd));

                    /* copy signature from shared buffer*/
                    memcpy(cmd->response, ipc->response, sizeof(ipc->response));
                }
                else
                {
                    SET_REE_HDR(hdr, REE_TEE_PUF_RESP, TEE_IPC_CMD_ERR,
                                REE_HDR_LEN);
                }
            }
        }
        break;
        case REE_TEE_NVM_PARAM_REQ:
        {
            struct ree_tee_nvm_param_cmd *cmd = (struct ree_tee_nvm_param_cmd *)ree_msg_buf;

            /* header only, no params for req */

            if (recv != sizeof(struct ree_tee_nvm_param_cmd)) {
                ZF_LOGI("Invalid Message size");
                SET_REE_HDR(hdr, REE_TEE_NVM_PARAM_RESP, TEE_INVALID_MSG_SIZE,
                            REE_HDR_LEN);
            } else {
                /*call to sys app*/

                ZF_LOGI("Send msg to sys app...");
                msg_info = seL4_MessageInfo_new(0, 0, 0, 1);

                seL4_SetMR(0, IPC_CMD_SYS_CTL_NVM_PARAM_REQ);

                msg_info = seL4_Call(ipc_app_ep1, msg_info);

                ZF_LOGI("Sys app responce received...");
                msg_len = seL4_MessageInfo_get_length(msg_info);
                if (msg_len > 0) {
                    msg_data = seL4_GetMR(0);
                }
                if (msg_data == IPC_CMD_SYS_CTL_NVM_PARAM_RESP)
                {
                    SET_REE_HDR(hdr, REE_TEE_NVM_PARAM_RESP, TEE_OK,
                                sizeof(struct ree_tee_nvm_param_cmd));

                    /* copy nvm parameter data from shared buffer*/
                    memcpy(cmd->response, app_shared_memory, NVM_PARAM_LENGTH);
                }
                else
                {
                    SET_REE_HDR(hdr, REE_TEE_NVM_PARAM_RESP, TEE_IPC_CMD_ERR,
                                REE_HDR_LEN);
                }
            }
        }
        break;
        default:
            /* leave original msg type to response */
            hdr->status = TEE_UNKNOWN_MSG;
            hdr->length = REE_HDR_LEN;
    }

    ZF_LOGI("Send message to REE, type %d , status %d , length %u ",
            hdr->msg_type, hdr->status, hdr->length);

    sel4_write_to_circ(&comm.tee2ree, hdr->length, (void *)hdr, &writer_lock);

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

        res = sel4_read_from_circ(&comm.ree2tee, comm.ree2tee.buf_len, ree_msg_buf,
                             &recv, &reader_lock);
        if (res) {
            continue;
        }

        /* Each message must contain at least header */
        if (recv < (int32_t)sizeof(struct ree_tee_hdr)) {
            ZF_LOGE("ERROR: package size %d", recv);
            continue;
        }

        res = handle_ree_msg(recv);
    }
    return 0;
}

static void recv_from_app(void)
{
    seL4_MessageInfo_t msg_info = {0};
    seL4_Word msg_len = 0;
    seL4_Word sender_badge = 0;
    seL4_Word msg_data = 0;

    ZF_LOGI("Wait msg from app...");
    msg_info = seL4_Recv(ipc_app_ep1, &sender_badge);
    msg_len = seL4_MessageInfo_get_length(msg_info);

    if (msg_len > 0) {
        msg_data = seL4_GetMR(0);
    }

    ZF_LOGI("msg from 0x%lx (%ld) 0x%lx", sender_badge, msg_len, msg_data);

    msg_info = seL4_MessageInfo_new(0, 0, 0, 1);
    msg_data++;
    seL4_SetMR(0, msg_data);

    seL4_Reply(msg_info);
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
        ZF_LOGF("Invalid root endpoint");
        return -EFAULT;
    }

    ZF_LOGI("ipc_root_ep: %p", (void *)ipc_root_ep);

    /* Wait shared memory config from rootserver and init tee2ree channel */
    error = setup_comm_ch();
    if (error) {
        return error;
    }

    /* Wait rpmsg config from rootserver */
    error = setup_ihc_buf(&comm.rpmsg_conf);
    if (error) {
        return error;
    }

    error = setup_app_ep();
    if (error) {
        return error;
    }

    /* Ping-pong IPC */
    recv_from_app();

    /* Wait linux to init ree2tee channel */
    error = wait_ree_setup();
    if (error) {
        return error;
    }

    error = wait_ree_msg();

    return error;
}