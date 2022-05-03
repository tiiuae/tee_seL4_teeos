#
# Copyright 2022, Unikie
#
# SPDX-License-Identifier: BSD-2-Clause
#

add_compile_options(
    -Werror
    -Wall
    -Wextra
)

add_compile_definitions(
    TRACE_ERROR_HIGHLIGHT
)

add_library(teeos_service STATIC
    teeos_service.c
)

target_include_directories(teeos_service
    PUBLIC
        ${SEL4_TEEOS_INCLUDE}
)

target_link_libraries(teeos_service
    PRIVATE
        muslc
        sel4_teeos_Config
        opteecrypt
)

add_library(sys_ctl_services STATIC
    sys_ctl_services.c
)

target_include_directories(sys_ctl_services
    PUBLIC
        ${SEL4_TEEOS_INCLUDE}
)

target_link_libraries(sys_ctl_services
    PRIVATE
        muslc
        sel4platsupport
        sel4_autoconf
        sel4_teeos_Config
)

add_library(pkcs11_service STATIC
    pkcs11_service.c
    sel4_optee_serializer.c
)

target_include_directories(pkcs11_service
    PUBLIC
        ${SEL4_TEEOS_INCLUDE}
)

target_link_libraries(pkcs11_service
    PRIVATE
        muslc
        sel4_teeos_Config
        opteecrypt
)
