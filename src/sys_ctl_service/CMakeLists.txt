#
# Copyright 2022, Unikie
#
# SPDX-License-Identifier: BSD-2-Clause
#

add_library(sysctllib STATIC
    sys_ctl_services.c
)

target_compile_options(sysctllib
    PRIVATE
        -Werror
        -Wall
        -Wextra
)
target_compile_definitions(sysctllib
    PRIVATE
        TRACE_ERROR_HIGHLIGHT
)

target_include_directories(sysctllib
    PRIVATE
        ${SEL4_TEEOS_INCLUDE}
)

target_link_libraries(sysctllib
    PRIVATE
        muslc
        sel4
        sel4runtime
        sel4utils
        sel4platsupport
        sel4_autoconf
        sel4_teeos_Config
)
