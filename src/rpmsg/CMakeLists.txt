add_library(rpmsg_lite STATIC
    common/llist.c
    rpmsg_lite/porting/environment/rpmsg_env_sel4.c
    rpmsg_lite/porting/platform/microchip/miv/rpmsg_platform_sel4.c
    rpmsg_lite/rpmsg_lite.c
    rpmsg_lite/rpmsg_ns.c
    rpmsg_lite/rpmsg_queue.c
    virtio/virtqueue.c
    rpmsg_sel4.c
)

target_compile_definitions(rpmsg_lite PRIVATE
    TRACE_ERROR_HIGHLIGHT
)

list(APPEND rpmsg_include_dirs
    "${PROJECT_SOURCE_DIR}/include"
    "${PROJECT_SOURCE_DIR}/include/rpmsg_lite"
    "${PROJECT_SOURCE_DIR}/include/rpmsg_lite/config"
    "${PROJECT_SOURCE_DIR}/include/rpmsg_lite/rpmsg"
    "${PROJECT_SOURCE_DIR}/include/rpmsg_lite/rpmsg/platform/microchip/miv"
)

target_include_directories(rpmsg_lite
    INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE
        ${rpmsg_include_dirs}
)

target_link_libraries(rpmsg_lite
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
