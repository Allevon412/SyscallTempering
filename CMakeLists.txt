cmake_minimum_required(VERSION 3.28)
project(SyscallTempering)

set(CMAKE_CXX_STANDARD 20)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fpermissive")

add_executable(SyscallTempering main.cpp
        src/syscalls.cpp
        include/syscalls.h
        src/PeParsing.cpp
        include/PeParsing.h
        src/helpers.cpp
        include/helpers.h)
