#!/usr/bin/env bash

cd build

export DYNINSTAPI_RT_LIB=/usr/local/lib/libdyninstAPI_RT.so
export LD_LIBRARY_PATH=/usr/local/lib:.
export AFL_SKIP_BIN_CHECK=1

clang -g -o example ../example.c
./afl-dyninst -i example -o example_inst
mkdir in
echo "a" > in/a
afl-fuzz -i in -o out -- ./example_inst
