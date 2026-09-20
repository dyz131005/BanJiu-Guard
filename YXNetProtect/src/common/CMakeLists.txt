# 公共库：特征库 + 规则引擎 + 启发式引擎（用户态）
add_library(yx_common STATIC
    yx_rules.cpp
    yx_heuristic.cpp
)

target_include_directories(yx_common PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_definitions(yx_common PUBLIC UNICODE _UNICODE)
