#
# Copyright 2019, Data61, CSIRO (ABN 41 687 119 230)
# Copyright 2021, Unikie
#
# SPDX-License-Identifier: BSD-2-Clause
#

cmake_minimum_required(VERSION 3.7.2)

set(project_dir "${CMAKE_CURRENT_LIST_DIR}/../..")
file(GLOB project_modules ${project_dir}/projects/*)
list(
    APPEND
        CMAKE_MODULE_PATH
        ${project_dir}/kernel
        ${project_dir}/tools/seL4/cmake-tool/helpers/
        ${project_dir}/tools/seL4/elfloader-tool/
        ${project_dir}/tools/seL4/gen_hss_payload/
        ${project_modules}
)

list(
    REMOVE_ITEM
        CMAKE_MODULE_PATH
        ${project_dir}/projects/sel4test
)

set(NANOPB_SRC_ROOT_FOLDER "${project_dir}/tools/nanopb" CACHE INTERNAL "")

set(SEL4_CONFIG_DEFAULT_ADVANCED ON)

include(application_settings)

set(RELEASE OFF CACHE BOOL "Performance optimized build")
set(VERIFICATION OFF CACHE BOOL "Only verification friendly kernel features")
set(KernelSel4Arch "" CACHE STRING "aarch32, aarch64, arm_hyp, ia32, x86_64, riscv32, riscv64")
set(PLATFORM "polarfire" CACHE STRING "Platform to test" FORCE)
set(KernelRiscvExtD ON CACHE BOOL "")
set(UseRiscVOpenSBI OFF CACHE BOOL "")
set(IMAGE_START_ADDR "0x80200000" CACHE STRING "")
set(RISCV64 ON CACHE BOOL "")
set(PolarfireAmp ON CACHE BOOL "")
add_compile_definitions(KERNEL_ELF_PADDR_BASE_START=0x400000)

correct_platform_strings()

find_package(seL4 REQUIRED)
sel4_configure_platform_settings()

set(valid_platforms ${KernelPlatform_all_strings} ${correct_platform_strings_platform_aliases})
set_property(CACHE PLATFORM PROPERTY STRINGS ${valid_platforms})
if(NOT "${PLATFORM}" IN_LIST valid_platforms)
    message(FATAL_ERROR "Invalid PLATFORM selected: \"${PLATFORM}\"
Valid platforms are: \"${valid_platforms}\"")
endif()

ApplyCommonReleaseVerificationSettings(${RELEASE} ${VERIFICATION})

set(KernelNumDomains 1 CACHE STRING "" FORCE)
set(KernelMaxNumNodes 1 CACHE STRING "" FORCE)

set(KernelHssIhcSyscall ON CACHE BOOL "")
