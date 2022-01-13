#
# Copyright 2021, Unikie
#
# SPDX-License-Identifier: BSD-2-Clause
#

cmake_minimum_required(VERSION 3.14)

project(ringbuffer_test C CXX ASM)

set(CMAKE_CXX_STANDARD 11)

add_compile_options(
#    -Werror    warning in spinlock.h
    -Wall
    -Wextra
    -O2
    -g
)

include(FetchContent)
FetchContent_Declare(
  googletest
  # Specify the commit you depend on and update it regularly.
  URL https://github.com/google/googletest/archive/609281088cfefc76f9d0ce82e1ff6c30cc3591e5.zip
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# # Now simply link against gtest or gtest_main as needed. Eg
add_executable(
    ringbuffer_test
        ringbuffer_test.cpp
        ringbuffer.c
)
target_include_directories(
    ringbuffer_test PRIVATE
        "include"
        "../include"
        "../../util_libs/libplatsupport/include"
)

target_link_libraries(ringbuffer_test gtest_main)
