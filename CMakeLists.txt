cmake_minimum_required(VERSION 3.13)
project(TestHooks
       VERSION 0.1
       DESCRIPTION "Hooks for end to end automated testing"
       LANGUAGES CXX)

add_definitions("/std:c++latest")

include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup()

add_library(TestHooks STATIC "")
target_link_libraries(TestHooks ${CONAN_LIBS})

add_subdirectory(Source)
add_subdirectory(Tests)
