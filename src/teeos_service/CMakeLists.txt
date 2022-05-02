#
# Copyright 2022, Unikie
#
# SPDX-License-Identifier: BSD-2-Clause
#

add_library(teeos_service STATIC
    teeos_service.c
)

target_compile_options(teeos_service
    PRIVATE
        -Werror
        -Wall
        -Wextra
)
target_compile_definitions(teeos_service
    PRIVATE
        TRACE_ERROR_HIGHLIGHT
)

target_include_directories(teeos_service
    PRIVATE
        ${SEL4_TEEOS_INCLUDE}
)

target_link_libraries(teeos_service
    PRIVATE
        muslc
        sel4
        sel4runtime
        sel4utils
        sel4platsupport
        sel4_autoconf
        sel4_teeos_Config
        opteecrypt
)
