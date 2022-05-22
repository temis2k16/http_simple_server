cmake_minimum_required(VERSION 3.17)
project(Adguard)

set(CMAKE_CXX_STANDARD 17)

SET(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -lpthread")

add_executable(Adguard main.cpp sha1.h sha1.cpp)
