#
# Copyright 2021, Unikie
#
# SPDX-License-Identifier: BSD-2-Clause
#

project(sel4_teeos C CXX ASM)

set(configure_string "")

# rdtime-counter frequency
config_set(HwTimerFreq HW_TIMER_FREQ 1000000)

add_config_library(sel4_teeos "${configure_string}")

add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/src/rpmsg" rpmsg_lite)

add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/src/sys_ctl_service" sys_ctl_service)
