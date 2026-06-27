cmake_minimum_required(VERSION 3.22)
project("native" C CXX)

add_library(native SHARED
    native_crypto.cpp
)

target_include_directories(native PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# 使用自带的 AES 实现（无需外部库），仅链接 Android log 库
target_link_libraries(native
    log
)
