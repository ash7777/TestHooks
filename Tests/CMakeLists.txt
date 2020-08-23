cmake_minimum_required(VERSION 2.8.12)
cmake_policy(SET CMP0048 NEW)
cmake_policy(SET CMP0076 NEW)

enable_testing()

add_definitions("/std:c++latest")

add_executable(TestHooksTests "")
target_sources(TestHooksTests PRIVATE
       Tests.cpp)

target_link_libraries(TestHooksTests
                      TestHooks
                      libboost_test_exec_monitor)

target_include_directories(TestHooksTests PRIVATE ${BOOST_INCLUDE_DIRS})
add_test(NAME test1 COMMAND TestHooksTests)

