#!/bin/sh
clang++ src/main.cpp src/test/test.cpp src/test/ecb.cpp src/lib/aes.cpp -o crypter -ggdb -std=c++11
