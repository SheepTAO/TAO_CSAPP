cmake_minimum_required(VERSION 3.22)
project(csapp)

add_subdirectory(test)
add_subdirectory(AssemblerSimulator)
add_subdirectory(ch3)

add_compile_options(-Wall -g -O2)