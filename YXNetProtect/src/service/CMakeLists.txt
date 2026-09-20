# 实时防护服务（用户态系统服务逻辑库）
add_library(yx_service STATIC
    yx_service.cpp
    yx_first_run.cpp
)

target_include_directories(yx_service PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src/common
)

target_link_libraries(yx_service PUBLIC yx_common)

# Windows 内核通信相关库
target_link_libraries(yx_service PUBLIC
    FltLib
    advapi32
    iphlpapi
    ws2_32
    wintrust
    crypt32
    psapi
)
