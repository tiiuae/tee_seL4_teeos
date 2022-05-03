#
# Copyright 2022, Unikie
#
# SPDX-License-Identifier: BSD-2-Clause
#

set(SEL4_TEEOS_DIR "${CMAKE_CURRENT_LIST_DIR}" CACHE STRING "")
set(SEL4_TEEOS_INCLUDE "${CMAKE_CURRENT_LIST_DIR}/include" CACHE STRING "")
set(LITTLEFS_SRC_FOLDER "${CMAKE_CURRENT_LIST_DIR}/../../projects/littlefs" CACHE INTERNAL "")
set(OPTEE_SRC_FOLDER "${CMAKE_CURRENT_LIST_DIR}/../../projects/crypto/optee_os" CACHE INTERNAL "")

mark_as_advanced(SEL4_TEEOS_DIR SEL4_TEEOS_PATH)

function(sel4_teeos_import_project)
    include("${SEL4_TEEOS_DIR}/sel4_teeos.cmake")
endfunction()

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(sel4_teeos
    DEFAULT_MSG
    SEL4_TEEOS_DIR
    SEL4_TEEOS_INCLUDE
)
