cmake_minimum_required(VERSION 3.5)
project(JCrypter)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES JCryptTest.cpp lib/aes.h lib/test.cpp lib/aes.cpp jcrypt.h jcrypt.cpp)
add_executable(JCrypter ${SOURCE_FILES})