cmake_minimum_required(VERSION 3.13)

add_definitions("/std:c++latest")

target_sources(TestHooks PUBLIC
       Hooks.cpp)

include_directories(.)
target_include_directories(TestHooks
                           PUBLIC .)

target_link_libraries(TestHooks MinHook)

add_subdirectory(MinHook)
