# afl-dyninst - AFL + Dyninst for fuzzing blackbox binary

This tool is actually forked from [afl-dyninst](https://github.com/vanhauser-thc/afl-dyninst). Many thanks to vanhauser-thc and talos-vulndev.

I just modified it to fit my own.

## Prerequisites

- AFL

Get [AFL 2.52b](http://lcamtuf.coredump.cx/afl/) or [AFL plusplus](https://github.com/vanhauser-thc/AFLplusplus), build and install.

- Dyninst 10

Get the Dyninst 10 release [source](https://github.com/dyninst/dyninst/releases/tag/v10.1.0), build and install.

## Building

Modify CMakeLists.txt. Reset `DYNINST_ROOT`, `DYNINST_BUILD` and `AFL_ROOT` to fit your environment.

Use cmake and ninja:

```shell
$ mkdir build && cd build
$ CC=gcc CXX=g++ cmake -G Ninja ..
$ ninja
```

## Usage

```shell
$ export DYNINSTAPI_RT_LIB=/usr/local/lib/libdyninstAPI_RT.so
$ export LD_LIBRARY_PATH=/usr/local/lib:.
$ export AFL_SKIP_BIN_CHECK=1
$ ./afl-dyninst -i [TARGET] -o [INSTRUMENTED]
$ afl-fuzz -i in -o out -- [INSTRUMENTED]
```

## Example

```shell
$ chmod +x example.sh
$ ./example.sh
```
