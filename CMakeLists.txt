cmake_minimum_required(VERSION 3.5)
project(SimpleAES)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES lib/aes.h lib/test.cpp lib/aes.cpp SAES.cpp SAESTest.cpp)
add_executable(SimpleAES ${SOURCE_FILES})