#
# Copyright 2021, Unikie
#
# SPDX-License-Identifier: BSD-2-Clause
#

cmake_minimum_required(VERSION 3.7.2)

include(settings.cmake)

project(teeos_amp C CXX ASM)

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

add_config_library(teeos "${configure_string}")

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
#    -Werror # spinlock.h: warning: unused parameter
    -Wall
    -Wextra
    -g
)

# RPMSG
add_library(sysctllib STATIC
    src/sys_ctl_services.c
)
target_include_directories(sysctllib
    PRIVATE
        "include"
)
target_link_libraries(sysctllib
    PUBLIC
        muslc
        sel4
        sel4runtime
        sel4utils
        sel4platsupport
        sel4_autoconf
    PRIVATE
        teeos_Config
)

add_subdirectory(src/rpmsg)
list(APPEND rpmsg_inc
    "${PROJECT_SOURCE_DIR}/include/rpmsg_lite"
    "${PROJECT_SOURCE_DIR}/include/rpmsg_lite/rpmsg"
    "${PROJECT_SOURCE_DIR}/include/rpmsg_lite/config"
    "${PROJECT_SOURCE_DIR}/include/rpmsg_lite/rpmsg/platform/microchip/miv"
)

#libtomcrypt

add_subdirectory(src/libtommath)
add_subdirectory(src/libtomcrypt)
add_subdirectory(src/optee_crypto)

list(APPEND libtomcrypt_inc
"${TOMCRYPT_SRC_FOLDER}/src/headers"
)

# TEE2REE communication app
add_executable(teeos_comm_app EXCLUDE_FROM_ALL
    src/comm_app.c
)

target_compile_options(teeos_comm_app
    PRIVATE
    ${ExtraCompileOptions}
)

target_include_directories(teeos_comm_app
    PRIVATE
        "include"
        "${rpmsg_inc}"
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
        teeos_Config
        rpmsg_lite
)

# APP2
add_executable(sys_ctl_app EXCLUDE_FROM_ALL
    src/sys_ctl_app.c
    src/key_service.c
    src/pkcs11_service.c
    src/sel4_optee_serializer.c
)

target_compile_options(sys_ctl_app
    PRIVATE
    ${ExtraCompileOptions}
)

target_include_directories(sys_ctl_app
    PRIVATE
        "include"
        "${libtomcrypt_inc}"
        "${OPTEE_SRC_FOLDER}/core/include"
        "src/optee_crypto"
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
        teeos_Config
        sysctllib
        tomcrypt
        opteecrypt
        tommath
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

target_include_directories(teeos_root
    PRIVATE
        "include"
        "${rpmsg_inc}"
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
        teeos_Config
        rpmsg_lite
)

# Set this image as the rootserver
include(rootserver)
DeclareRootserver(teeos_root)

# Generate HSS payload binary. Only seL4 image is included.
find_package(gen_hss_payload REQUIRED)
gen_hss_payload_import_project()
