#!/bin/sh
CODE_FILES="src/main.cpp \
            src/crypter.cpp \
            src/test/test.cpp \
            src/test/ecb.cpp \
            src/test/utils.cpp \
            src/test/lib.cpp \
            src/lib/aes.cpp"
clang++ $CODE_FILES -o crypter -ggdb -std=c++11
