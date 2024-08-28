cmake_minimum_required(VERSION 3.10)

project(infotecs_test VERSION 0.1) 


set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0 -Wall -Wextra -Wpedantic")

set(SOURCE_FILES
    main.cpp
    utils.cpp
    utils.h
    )


find_package(PkgConfig REQUIRED)
pkg_search_module(PCAP REQUIRED libpcap)

add_executable(infotecs_test ${SOURCE_FILES})

target_include_directories(infotecs_test PRIVATE ${PCAP_INCLUDE_DIRS})
target_link_libraries(infotecs_test PRIVATE ${PCAP_LIBRARIES})

