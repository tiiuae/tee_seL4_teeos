/*
 * Copyright 2021, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/* HSS example -->*/

#include <sel4_teeos/gen_config.h>

#include <regex.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <stdint.h>
#include <sel4runtime.h>

#include <teeos_common.h>
#include <sys_ctl_service.h>

#include <utils/fence.h>
#include <utils/zf_log.h>

#include "spinlock.h"
#include <utils/arith.h>

/* In polling mode only one request at time so commmand can be placed in zero offset */
#define MBOX_OFFSET 0


static uint32_t *mbox_base;
static uint32_t *msg_int_reg;
struct sbcctrl_t *sbcctrl;

void set_sys_ctl_address(uint32_t *sys_b, uint32_t *mb_b, uint32_t *mint_reg)
{
    mbox_base = mb_b;
    msg_int_reg = mint_reg;
    sbcctrl = (struct sbcctrl_t *)sys_b;
}

static int request_system_service
(
    uint8_t cmd_opcode,
    uint8_t* cmd_data,
    uint16_t cmd_data_size,
    uint8_t* p_response,
    uint16_t response_size,
    uint16_t mb_offset,
    uint16_t response_offset

)
{
    uint32_t idx;
    uint16_t ss_command = 0u;
    uint32_t* word_buf ;
    uint8_t* byte_buf ;
    uint8_t byte_off;
    uint8_t byte_index;
    uint32_t * mailbox_reg;
    uint32_t mailbox_val = 0u;

    UNUSED_VAR(p_response);
    UNUSED_VAR(response_size);
    UNUSED_VAR(response_offset);


    if (sbcctrl->SERVICES_SR & SCBCTRL_SERVICESSR_BUSY_MASK)
    {
        /*System controller is busy with executing service*/
        return -EBUSY;
    }

    /*Code for MSS_SYS_PARAM_ERR is not implemented with this version of driver.*/

    /* *msg_int_reg = 0x0u; */ /*clear message_int reg*/


    if (cmd_data_size > 0u)
    {
        word_buf = (uint32_t*)cmd_data;

        /* Write the user data into mail box. */
        for (idx = 0u; idx < (cmd_data_size / 4u); idx++)
        {
            *(mbox_base+ idx) = word_buf[idx];
        }

        if ((cmd_data_size % 4u) > 0u)
        {
             byte_off = (((cmd_data_size / 4u) * 4u));
             byte_buf = (uint8_t*)(cmd_data + byte_off);

             mailbox_reg = (mbox_base + idx);
             mailbox_val = *mailbox_reg;

             for (byte_index = 0u; byte_index < (cmd_data_size % 4u);
                  byte_index++)
             {
                 mailbox_val &= ~(0xffu << (byte_index * 8u));
                 mailbox_val |= (byte_buf[byte_index] << (byte_index * 8u));
             }
             *mailbox_reg = mailbox_val;
        }
    }

    /*Form the SS command: bit 0to6 is the opcode, bit 7to15 is the Mailbox
         offset For some services this field has another meaning.
        (e.g. for IAP bit-stream auth. it means spi_idx)*/
    ss_command = ((mb_offset << 7u) |  (cmd_opcode & 0x7Fu));


    sbcctrl->SERVICES_CR = (((ss_command << SCBCTRL_SERVICESCR_COMMAND)
            & SCBCTRL_SERVICESCR_COMMAND_MASK) |
            SCBCTRL_SERVICESCR_REQ_MASK);



    /*Service requested successfully*/
    return 0;
}

static int execute_ss_polling_mode
(
    uint8_t cmd_opcode,
    uint8_t* cmd_data,
    uint16_t cmd_data_size,
    uint8_t* p_response,
    uint16_t response_size,
    uint16_t mb_offset,
    uint16_t response_offset
)
{
    uint32_t idx;
    uint16_t status = 0u;
    uint16_t response_limit = 0u;
    uint8_t* response_buf;

    status = request_system_service(cmd_opcode, cmd_data, cmd_data_size,
                                   p_response,response_size, mb_offset,
                                   response_offset);

    if (status == 0)
    {
        /**REQ bit will remain set till the system controller starts
         * processing command. Since DRI is slow interface, we are waiting
         * here to make sure System controller has started processing
         * command*/
        while (SCBCTRL_SERVICESCR_REQ_MASK == (sbcctrl->SERVICES_CR &
                SCBCTRL_SERVICESCR_REQ_MASK))
        {
            ;
        }

        /*Once system controller starts processing command The busy bit will
         *  go 1. Make sure that service is complete i.e. BUSY bit is gone 0*/
        while (SCBCTRL_SERVICESSR_BUSY_MASK == (sbcctrl->SERVICES_SR &
                SCBCTRL_SERVICESSR_BUSY_MASK))
        {
            ;
        }

        if (response_size > 0u)
        {
            response_limit = response_size + response_offset;
            response_buf = (uint8_t*)p_response;

            for (idx = response_offset; idx < response_limit; idx++)
            {
                response_buf[idx - response_offset] =
                        *((uint8_t *)mbox_base + idx);
            }
        }

        /*Read the status returned by System Controller*/
        status = ((sbcctrl->SERVICES_SR & SCBCTRL_SERVICESSR_STATUS_MASK) >>
                SCBCTRL_SERVICESSR_STATUS);
    }
    else
    {
        status = -EBUSY;
    }

    return status;
}

int get_serial_number(uint8_t * p_serial_number)
{
    int status = 0;

    status = execute_ss_polling_mode(
            (uint8_t)MSS_SYS_SERIAL_NUMBER_REQUEST_CMD,
            NULL_BUFFER,
            MSS_SYS_WITHOUT_CMD_DATA,
            p_serial_number,
            (uint16_t)MSS_SYS_SERIAL_NUMBER_RESP_LEN,
            MBOX_OFFSET,
            MSS_SYS_COMMON_RET_OFFSET);


    return status;
}

int nonce_service(uint8_t * p_nonce)
{
    int status = -1;

    if (p_nonce  == NULL_BUFFER)
    {
        return -EINVAL;
    }

    status = execute_ss_polling_mode(
            (uint8_t)MSS_SYS_NONCE_SERVICE_REQUEST_CMD,
            NULL_BUFFER,
            MSS_SYS_WITHOUT_CMD_DATA,
            p_nonce,
            (uint16_t)MSS_SYS_NONCE_SERVICE_RESP_LEN,
            MBOX_OFFSET,
            MSS_SYS_COMMON_RET_OFFSET);


    return status;
}

int read_nvm_parameters(uint8_t *resp)
{
    int status = -1;

    if (resp  == NULL_BUFFER)
    {
        return -EINVAL;
    }

    status = execute_ss_polling_mode(
            (uint8_t)MSS_SYS_READ_ENVM_PARAM_REQUEST_CMD,
            NULL_BUFFER,
            MSS_SYS_WITHOUT_CMD_DATA,
            resp,
            (uint16_t)MSS_SYS_READ_ENVM_PARAM_RESP_LEN,
            MBOX_OFFSET,
            MSS_SYS_COMMON_RET_OFFSET);

    return status;
}

int digital_signature_service
(
    uint8_t* p_hash,
    uint8_t format,
    uint8_t* p_response
)
{
    int status = -1;
    uint16_t resp_length = 0;

    if (format == MSS_SYS_DIGITAL_SIGNATURE_RAW_FORMAT_REQUEST_CMD) {
        resp_length = MSS_SYS_DIGITAL_SIGNATURE_RAW_FORMAT_RESP_SIZE;
    } else if (format == MSS_SYS_DIGITAL_SIGNATURE_DER_FORMAT_REQUEST_CMD) {
        resp_length = MSS_SYS_DIGITAL_SIGNATURE_DER_FORMAT_RESP_SIZE;
    } else {
        return -EINVAL;
    }


    status = execute_ss_polling_mode
                (format,
                p_hash,
                (uint16_t)MSS_SYS_DIGITAL_SIGNATURE_HASH_DATA_LEN,
                p_response,
                resp_length,
                MBOX_OFFSET,
                (uint16_t)MSS_SYS_DIGITAL_SIG_RET_OFFSET);

    return status;
}


int secure_nvm_write
(
    uint8_t format,
    uint8_t snvm_module,
    uint8_t* p_data,
    uint8_t* p_user_key
)
{
    uint8_t frame[256] = {0x00};
    uint8_t* p_frame = &frame[0];
    uint16_t index = 0;
    int status = -1;

    if((!p_data) ||(snvm_module >= 221))
    {
        return -EINVAL;
    }

    *p_frame = snvm_module; /*SNVMADDR - SNVM module*/
    p_frame += 4; /* Next 3 bytes RESERVED - For alignment */

    /* Copy user key and send the command/data to mailbox. */
    if ((format == MSS_SYS_SNVM_AUTHEN_TEXT_REQUEST_CMD) ||
       (format == MSS_SYS_SNVM_AUTHEN_CIPHERTEXT_REQUEST_CMD))
    {

        if (!p_user_key)
            return -EINVAL;
        /* Copy user data */
        for (index = 0u; index < (MSS_SYS_AUTHENTICATED_TEXT_DATA_LEN
                - MSS_SYS_USER_SECRET_KEY_LEN - 4); index++)
        {
            *p_frame = p_data[index];
            p_frame++;
        }

        /* Copy user key */
        for (index = 0u; index < MSS_SYS_USER_SECRET_KEY_LEN; index++)
        {
            *p_frame = p_user_key[index];
            p_frame++;
        }

        status = execute_ss_polling_mode(
                    format,
                    &frame[0],
                    (uint16_t)MSS_SYS_AUTHENTICATED_TEXT_DATA_LEN,
                    NULL_BUFFER,
                    MSS_SYS_NO_RESPONSE_LEN,
                    MBOX_OFFSET,
                    MSS_SYS_COMMON_RET_OFFSET);

    }
    else
    {
        /* Copy user data */
        for (index = 0u; index < (MSS_SYS_NON_AUTHENTICATED_TEXT_DATA_LEN - 4u);
                index++)
        {
            *(p_frame+index) = p_data[index];
        }


        status = execute_ss_polling_mode(
                format,
                &frame[0],
                (uint16_t)MSS_SYS_NON_AUTHENTICATED_TEXT_DATA_LEN,
                NULL_BUFFER,
                MSS_SYS_NO_RESPONSE_LEN,
                MBOX_OFFSET,
                MSS_SYS_COMMON_RET_OFFSET);

    }

    return status;
}

int secure_nvm_read
(
    uint8_t snvm_module,
    uint8_t* p_user_key,
    uint8_t* p_admin,
    uint8_t* p_data,
    uint16_t data_len
)
{
    /* Frame the message. */
    uint8_t frame[16] = {0x00u};
    uint8_t* p_frame = &frame[0];
    uint16_t index = 0u;
    int status = -1;
    uint8_t response[256] = {0x00};

    if((!p_data) || (!p_admin) || (snvm_module >= 221))
    {
        return -EINVAL;
    }

    *p_frame = snvm_module; /*SNVMADDR - SNVM module*/
    p_frame += 4u; /* RESERVED - For alignment */

    /* Copy user key */
    if (236u == data_len)
    {
        if (!p_user_key)
            return -EINVAL;

        for (index = 0u; index < 12u; index++)
        {
            *p_frame = p_user_key[index];
            p_frame++;
        }
    }
    else
    {
        p_frame += 12u;
    }
    status = execute_ss_polling_mode(
                (uint8_t)MSS_SYS_SNVM_READ_REQUEST_CMD,
                &frame[0],
                (uint16_t)MSS_SYS_SECURE_NVM_READ_DATA_LEN,
                response,
                (data_len + 4u),
                MBOX_OFFSET,
                (uint16_t)MSS_SYS_SECURE_NVM_READ_RET_OFFSET);


    if (!status)
    {
        for (index = 0u; index < 4u; index++)
        {
            *(p_admin+index) = (uint32_t)response[index];
        }

       /* Copy data into user buffer. */
        for (index = 4u; index < (data_len + 4u); index++)
        {
            *(p_data + (index - 4u)) = response[index];
        }
    }

    return status;
}

int puf_emulation_service
(
    uint8_t * p_challenge,
    uint8_t op_type,
    uint8_t* p_response
)
{
    int status = -1;
    uint8_t mb_format[20] = {0x00};


    /* Frame the data required for mailbox */
    mb_format[0] = op_type;

    for (int index = 4; index < 20; index++)
    {
        mb_format[index] = p_challenge[index - 4u];
    }

    status = execute_ss_polling_mode(
                (uint8_t)MSS_SYS_PUF_EMULATION_SERVICE_REQUEST_CMD,
                mb_format,
                (uint16_t)MSS_SYS_PUF_EMULATION_SERVICE_CMD_LEN,
                p_response,
                (uint16_t)MSS_SYS_PUF_EMULATION_SERVICE_RESP_LEN,
                MBOX_OFFSET,
                (uint16_t)MSS_SYS_PUF_EMULATION_RET_OFFSET);

    return status;
}
