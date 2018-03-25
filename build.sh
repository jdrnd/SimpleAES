#!/bin/sh
CODE_FILES="src/main.cpp \
            src/crypter.cpp \
            src/helpers.cpp \
            test/test.cpp \
            test/ecb.cpp \
            test/cbc.cpp \
            test/utils.cpp \
            test/lib.cpp \
            lib/aes.cpp"
clang++ $CODE_FILES -o bin/crypter -ggdb -std=c++11
