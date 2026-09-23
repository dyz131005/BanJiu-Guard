# 公共库：特征库 + 规则引擎 + 启发式引擎 + ML 引擎（用户态）
add_library(yx_common STATIC
    yx_rules.cpp
    yx_heuristic.cpp
    yx_ml_engine.cpp
)

target_include_directories(yx_common PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/third_party/LightGBM/include
)

# 静态链接 LightGBM：消费侧不导出符号
target_compile_definitions(yx_common PUBLIC UNICODE _UNICODE LIGHTGBM_STATIC_LIB)
