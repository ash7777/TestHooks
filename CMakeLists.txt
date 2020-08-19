cmake_minimum_required(VERSION 2.8.12)
cmake_policy(SET CMP0048 NEW)
project(TestHooks
       VERSION 0.1
       DESCRIPTION "Hooks for end to end automated testing"
       LANGUAGES CXX)

add_definitions("-std=c++latest")

include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup()

add_library(TestHooks Hooks.cpp)
target_link_libraries(TestHooks ${CONAN_LIBS})
