#
# Copyright 2022, Unikie
#
# SPDX-License-Identifier: BSD-2-Clause
#

add_library(littlefs STATIC
    ${LITTLEFS_SRC_FOLDER}/lfs.c
    ${LITTLEFS_SRC_FOLDER}/lfs_util.c
    ${LITTLEFS_SRC_FOLDER}/bd/lfs_rambd.c
)

target_compile_options(littlefs
    PRIVATE
        ${ExtraCompileOptions}
)

target_include_directories(littlefs
    PUBLIC ${LITTLEFS_SRC_FOLDER}
)

target_link_libraries(littlefs
    PUBLIC
        muslc
)
