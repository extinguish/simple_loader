cmake_minimum_required(VERSION 3.17)
project(simple_loader)

set(CMAKE_CXX_STANDARD 14)

file(GLOB_RECURSE SRCFILES obj_loader/first_stage/*.c
        obj_loader/second_stage/*.c
        obj_loader/third_stage/*.c)

add_executable(simple_loader main.cpp ${SRCFILES})