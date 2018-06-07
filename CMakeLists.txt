cmake_minimum_required(VERSION 3.7)
project(orm2_hello)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread -Wall ")
set(SOURCE_FILES main.c)
add_executable(orm2_hello ${SOURCE_FILES})
target_link_libraries(orm2_hello pcap)