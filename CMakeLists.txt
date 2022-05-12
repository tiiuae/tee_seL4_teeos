#
# Copyright 2021, Unikie
#
# SPDX-License-Identifier: BSD-2-Clause
#

cmake_minimum_required(VERSION 3.7.2)

include(settings.cmake)

project(sel4_teeos C CXX ASM)

set(SEL4_TEEOS_INCLUDE "${CMAKE_CURRENT_LIST_DIR}/include" CACHE STRING "")

set(LibUtilsDefaultZfLogLevel 3 CACHE INTERNAL "")

find_package(seL4 REQUIRED)
find_package(elfloader-tool REQUIRED)

set(KernelRootCNodeSizeBits 13 CACHE INTERNAL "")

sel4_import_kernel()

set(ElfloaderImage "binary" CACHE STRING "" FORCE)

elfloader_import_project()

set(configure_string "")

config_string(
    TeeCommAppName TEE_COMM_APP_NAME
    "TEE2REE communication app name"
    DEFAULT "teeos_comm_app")

config_string(
    SysAppName SYS_APP_NAME
    "System Control app name"
    DEFAULT "sys_ctl_app")

# rdtime-counter frequency
config_set(HwTimerFreq HW_TIMER_FREQ 1000000)

add_config_library(sel4_teeos "${configure_string}")

find_package(musllibc REQUIRED)
find_package(util_libs REQUIRED)
find_package(seL4_libs REQUIRED)
find_package(sel4_projects_libs REQUIRED)

set(UserLinkerGCSections OFF CACHE BOOL "" FORCE)

musllibc_setup_build_environment_with_sel4runtime()
sel4_import_libsel4()
util_libs_import_libraries()
sel4_libs_import_libraries()

set(LibNanopb ON CACHE BOOL "" FORCE)
sel4_projects_libs_import_libraries()

set(ExtraCompileOptions
    -Werror
    -Wall
    -Wextra
    -g
)

set(ExtraCompileDefinitions
    TRACE_ERROR_HIGHLIGHT
)

# RPMSG
add_subdirectory(src/rpmsg)

#libtomcrypt

add_subdirectory(src/libtommath)
add_subdirectory(src/libtomcrypt)
add_subdirectory(src/optee_crypto)

list(APPEND libtomcrypt_inc
"${TOMCRYPT_SRC_FOLDER}/src/headers"
)

# littlefs
add_subdirectory(src/littlefs)

# TEE2REE communication app
add_executable(teeos_comm_app EXCLUDE_FROM_ALL
    src/comm_app.c
)

target_compile_options(teeos_comm_app
    PRIVATE
    ${ExtraCompileOptions}
)

target_compile_definitions(teeos_comm_app PRIVATE
    ${ExtraCompileDefinitions}
)

target_include_directories(teeos_comm_app
    PRIVATE
        "include"
)

target_link_options(teeos_comm_app
    PRIVATE
        -Xlinker -Map=teeos_comm_app.map
)

target_link_libraries(teeos_comm_app
    PUBLIC
        sel4_autoconf
        muslc
        sel4
        sel4runtime
        sel4allocman
        sel4vka
        sel4utils
        sel4platsupport
        sel4muslcsys
        opteecrypt
    PRIVATE
        sel4_teeos_Config
        rpmsg_lite
        sel4_crashlog
)

add_subdirectory(src/teeos_service)

# APP2
add_executable(sys_ctl_app EXCLUDE_FROM_ALL
    src/sys_ctl_app.c
)

target_compile_options(sys_ctl_app
    PRIVATE
    ${ExtraCompileOptions}
)

target_compile_definitions(sys_ctl_app PRIVATE
    ${ExtraCompileDefinitions}
)

target_include_directories(sys_ctl_app
    PRIVATE
        "include"
)

target_link_options(sys_ctl_app
    PRIVATE
        -Xlinker -Map=sys_ctl_app.map
)

target_link_libraries(sys_ctl_app
    PUBLIC
        sel4_autoconf
        muslc
        sel4
        sel4runtime
        sel4allocman
        sel4vka
        sel4utils
        sel4platsupport
        sel4muslcsys
    PRIVATE
        sel4_teeos_Config
        tomcrypt
        opteecrypt
        tommath
        littlefs
        teeos_service
        sys_ctl_services
        pkcs11_service
        sel4_crashlog
)

# CPIO
include(cpio)
set(cpio_files "")
list(APPEND cpio_files
    "$<TARGET_FILE:${TeeCommAppName}>"
    "$<TARGET_FILE:${SysAppName}>"
)

MakeCPIO(apps.o "${cpio_files}")

# rootserver
add_executable(teeos_root EXCLUDE_FROM_ALL
    src/rootserver.c
    apps.o
)

target_compile_options(teeos_root
    PRIVATE
    ${ExtraCompileOptions}
    -Wno-unused-parameter
)

target_compile_definitions(teeos_root PRIVATE
    ${ExtraCompileDefinitions}
)

target_include_directories(teeos_root
    PRIVATE
        "include"
)

target_link_options(teeos_root
    PRIVATE
        -Xlinker -Map=teeos_root.map
)

target_link_libraries(teeos_root
    PUBLIC
        sel4_autoconf
        muslc
        sel4
        sel4runtime
        sel4allocman
        sel4vka
        sel4utils
        sel4platsupport
        sel4muslcsys
    PRIVATE
        sel4_teeos_Config
        rpmsg_lite
        sel4_crashlog
)

# Set this image as the rootserver
include(rootserver)
DeclareRootserver(teeos_root)

# Generate HSS payload binary. Only seL4 image is included.
find_package(gen_hss_payload REQUIRED)
gen_hss_payload_import_project()
