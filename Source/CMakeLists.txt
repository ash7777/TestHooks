cmake_minimum_required(VERSION 2.8.12)
cmake_policy(SET CMP0048 NEW)
cmake_policy(SET CMP0076 NEW)

add_definitions("-std=c++latest")

target_sources(TestHooks PUBLIC
       Hooks.cpp)

include_directories(.)
target_include_directories(TestHooks
                           PUBLIC .)

add_subdirectory(MinHook)
