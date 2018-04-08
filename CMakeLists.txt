cmake_minimum_required(VERSION 3.9)
project(SimpleAES CXX)

set(CMAKE_CXX_STANDARD 14)
include_directories( ${MY_SOURCE_DIR}/src )
include_directories(src lib test)

add_executable (crypter
        src/main.cpp
        src/crypter.cpp
        src/helpers.cpp
        src/utils.cpp
        lib/aes.cpp
        test/test.cpp
        test/lib.cpp
        test/utils.cpp
        test/ecb.cpp
        test/cbc.cpp
        test/pcbc.cpp)

set_target_properties(crypter PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY_DEBUG ../bin
        RUNTIME_OUTPUT_DIRECTORY_RELEASE ../bin
        )
