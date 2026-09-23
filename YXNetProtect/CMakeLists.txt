cmake_minimum_required(VERSION 3.16)
project(BanJiu-Guard LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---- 静态 Qt 路径（无 ICU，全静态；旧版 qt-static-msvc 含 ICU 依赖）----
if(NOT DEFINED QT_STATIC_PREFIX)
    set(QT_STATIC_PREFIX "D:/program/qt-static-msvc-noicu")
endif()
set(CMAKE_PREFIX_PATH "${QT_STATIC_PREFIX}")

# ---- 静态 CRT（与静态 Qt 匹配 /MT）----
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# ---- MSVC 编译选项 ----
if(MSVC)
    add_compile_options(/W3 /utf-8)
    add_compile_definitions(UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)
endif()

# ---- 静态 Qt 必需宏 ----
# QT_STATIC：标记静态构建（避免 __declspec(dllimport)）
# QT_STATICPLUGIN：让 Q_IMPORT_PLUGIN 宏真正展开（否则宏为空，插件永远不导入）
add_compile_definitions(QT_STATIC QT_STATICPLUGIN)

# ---- 子工程 ----
add_subdirectory(src/common)
add_subdirectory(src/service)
add_subdirectory(src/gui)
