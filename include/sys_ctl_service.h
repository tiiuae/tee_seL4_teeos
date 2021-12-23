/*
 * Copyright 2021, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <sel4/types.h>


typedef union
{
    uint16_t Data;
    struct
    {
        uint16_t mode : 7;      /* Mode from above */
        uint16_t mbox_addr : 9; /* 10:2 mbox address */
    } bits;
} sNvmFormat;

typedef union
{
    uint32_t Data;
    struct
    {
        uint32_t cycles : 20;
        uint32_t pagetype : 2;
        uint32_t reserved : 1;
        uint32_t romflag : 1;
        uint32_t unsed : 8;
    } bits;
}AdminData;

struct snvm_auth_write_data_t
{
    uint8_t page_addr;
    uint8_t reserved[3];
    uint8_t data[236];
    uint8_t usk[12];
};

struct snvm_auth_read_data_t
{
    uint8_t page_addr;
    uint8_t reserved[3];
    AdminData admin;
    uint8_t usk[12];
    uint8_t data[236];
};

#define UNUSED_VAR(x) (void)(x)

/* From HSS ---> */
struct sbcctrl_t
{
    volatile uint32_t SOFT_RESET;
    volatile uint32_t VDETECTOR;
    volatile uint32_t TVS_CONTROL;
    volatile uint32_t TVS_TEMP_A;
    volatile uint32_t TVS_TEMP_B;
    volatile uint32_t TVS_TEMP_C;
    volatile uint32_t TVS_VOLT_A;
    volatile uint32_t TVS_VOLT_B;
    volatile uint32_t TVS_VOLT_C;
    volatile uint32_t TVS_OUTPUT0;
    volatile uint32_t TVS_OUTPUT1;
    volatile uint32_t TVS_TRIGGER;
    volatile uint32_t TRIM_VDET1P05;
    volatile uint32_t TRIM_VDET1P8;
    volatile uint32_t TRIM_VDET2P5;
    volatile uint32_t TRIM_TVS;
    volatile uint32_t TRIM_GDET1P05;
    volatile uint32_t RESERVED0;
    volatile uint32_t RESERVED1;
    volatile uint32_t RESERVED2;
    volatile uint32_t SERVICES_CR;
    volatile uint32_t SERVICES_SR;
    volatile uint32_t USER_DETECTOR_SR;
    volatile uint32_t USER_DETECTOR_CR;
    volatile uint32_t MSS_SPI_CR;

};

/***************SCBCTRL  SERVICES_CR register*************************/
#define SCBCTRL_SERVICESCR_REQ                      (0u)
#define SCBCTRL_SERVICESCR_REQ_MASK                 (1u << SCBCTRL_SERVICESCR_REQ)

#define SCBCTRL_SERVICESCR_BUSY                     (1u)
#define SCBCTRL_SERVICESCR_BUSY_MASK                (1u << SCBCTRL_SERVICESCR_BUSY)

#define SCBCTRL_SERVICESCR_ABORT                    (2u)
#define SCBCTRL_SERVICESCR_ABORT_MASK               (1u << SCBCTRL_SERVICESCR_ABORT)

#define SCBCTRL_SERVICESCR_NOTIFY                   (3u)
#define SCBCTRL_SERVICESCR_NOTIFY_MASK              (1u << SCBCTRL_SERVICESCR_NOTIFY)

#define SCBCTRL_SERVICESCR_COMMAND                  (16u)
#define SCBCTRL_SERVICESCR_COMMAND_MASK             (0xFFFFu << SCBCTRL_SERVICESCR_COMMAND)


/***************SCBCTRL  SERVICES_SR registers*************************/
#define SCBCTRL_SERVICESSR_REQ                      (0u)
#define SCBCTRL_SERVICESSR_REQ_MASK                 (1u << SCBCTRL_SERVICESSR_REQ)

#define SCBCTRL_SERVICESSR_BUSY                     (1u)
#define SCBCTRL_SERVICESSR_BUSY_MASK                (1u << SCBCTRL_SERVICESSR_BUSY)

#define SCBCTRL_SERVICESSR_ABORT                    (2u)
#define SCBCTRL_SERVICESSR_ABORT_MASK               (1u << SCBCTRL_SERVICESSR_ABORT)

#define SCBCTRL_SERVICESSR_NOTIFY                   (3u)
#define SCBCTRL_SERVICESSR_NOTIFY_MASK              (1u << SCBCTRL_SERVICESSR_NOTIFY)

#define SCBCTRL_SERVICESSR_STATUS                   (16u)
#define SCBCTRL_SERVICESSR_STATUS_MASK              (0xFFFFu << SCBCTRL_SERVICESSR_STATUS)

/*-------------------------------------------------------------------------*//**
  Device and design information services request command opcodes
 */
#define MSS_SYS_SERIAL_NUMBER_REQUEST_CMD                       0x00u
#define MSS_SYS_USERCODE_REQUEST_CMD                            0x01u
#define MSS_SYS_DESIGN_INFO_REQUEST_CMD                         0x02u
#define MSS_SYS_DEVICE_CERTIFICATE_REQUEST_CMD                  0x03u
#define MSS_SYS_READ_DIGEST_REQUEST_CMD                         0x04u
#define MSS_SYS_QUERY_SECURITY_REQUEST_CMD                      0x05u
#define MSS_SYS_READ_DEBUG_INFO_REQUEST_CMD                     0x06u
#define MSS_SYS_READ_ENVM_PARAM_REQUEST_CMD                     0x07u

#define MSS_SYS_DIGITAL_SIGNATURE_RAW_FORMAT_REQUEST_CMD        0x19u
#define MSS_SYS_DIGITAL_SIGNATURE_DER_FORMAT_REQUEST_CMD        0x1Au
#define MSS_SYS_SNVM_NON_AUTHEN_TEXT_REQUEST_CMD                0x10u
#define MSS_SYS_SNVM_AUTHEN_TEXT_REQUEST_CMD                    0x11u
#define MSS_SYS_SNVM_AUTHEN_CIPHERTEXT_REQUEST_CMD              0x12u
#define MSS_SYS_SNVM_READ_REQUEST_CMD                           0x18u
#define MSS_SYS_PUF_EMULATION_SERVICE_REQUEST_CMD               0x20u
#define MSS_SYS_NONCE_SERVICE_REQUEST_CMD                       0x21u

#define MSS_SYS_WITHOUT_CMD_DATA                                0u

#define MSS_SYS_PUF_EMULATION_SERVICE_CMD_LEN                   20u
#define MSS_SYS_DIGITAL_SIGNATURE_HASH_DATA_LEN                 48u

/*SNVMADDR + RESERVED + PT*/
#define MSS_SYS_AUTHENTICATED_TEXT_DATA_LEN                     252u

/*SNVMADDR + RESERVED + PT + USK*/
#define MSS_SYS_NON_AUTHENTICATED_TEXT_DATA_LEN                 256u

#define MSS_SYS_SECURE_NVM_READ_DATA_LEN                        16u

#define MSS_SYS_NO_RESPONSE_LEN                                 0u
#define MSS_SYS_SERIAL_NUMBER_RESP_LEN                          16u
#define MSS_SYS_USERCODE_RESP_LEN                               4u
#define MSS_SYS_DESIGN_INFO_RESP_LEN                            36u
#define MSS_SYS_DEVICE_CERTIFICATE_RESP_LEN                     1024u
#define MSS_SYS_READ_DIGEST_RESP_LEN                            544u
#define MSS_SYS_QUERY_SECURITY_RESP_LEN                         33u
#define MSS_SYS_READ_DEBUG_INFO_RESP_LEN                        94u
#define MSS_SYS_NONCE_SERVICE_RESP_LEN                          32u
#define MSS_SYS_READ_ENVM_PARAM_RESP_LEN                        256u
#define MSS_SYS_PUF_EMULATION_SERVICE_RESP_LEN                  32u
#define MSS_SYS_DIGEST_CHECK_SERVICE_RESP_LEN                   4u
#define MSS_SYS_DIGITAL_SIGNATURE_RAW_FORMAT_RESP_SIZE          96u
#define MSS_SYS_DIGITAL_SIGNATURE_DER_FORMAT_RESP_SIZE          104u
#define MSS_SYS_USER_SECRET_KEY_LEN                             12u
#define MSS_SYS_PROBE_READ_SERVICE_RESP_LEN                     4u
#define MSS_SYS_GENERATE_OTP_RESP_LEN                           16u

#define MSS_SYS_COMMON_RET_OFFSET                               0u
#define MSS_SYS_DIGITAL_SIG_RET_OFFSET                          48u
#define MSS_SYS_SECURE_NVM_READ_RET_OFFSET                      16u
#define MSS_SYS_PUF_EMULATION_RET_OFFSET                        20u
#define MSS_SYS_DIGEST_CHECK_RET_OFFSET                         4u
#define MSS_SYS_GENERATE_OTP_RET_OFFSET                         20u

#define MSS_SYS_WITHOUT_CMD_DATA                                0u
#define NULL_BUFFER                                             (( uint8_t* ) 0)


/* functions */

int get_serial_number(uint8_t * p_serial_number);
int nonce_service(uint8_t * p_nonce);
int read_nvm_parameters(uint8_t *resp);
int secure_nvm_write(
    uint8_t format, 
    uint8_t snvm_module,
    uint8_t* p_data,
    uint8_t* p_user_key
);
int secure_nvm_read
(
    uint8_t snvm_module,
    uint8_t* p_user_key,
    uint8_t* p_admin,
    uint8_t* p_data,
    uint16_t data_len
);

int puf_emulation_service
(
    uint8_t * p_challenge,  /* 128bit input*/ 
    uint8_t op_type,
    uint8_t* p_response /* 256bit response */
);

void set_sys_ctl_address(uint32_t*, uint32_t*, uint32_t*);
