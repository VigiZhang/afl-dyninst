cmake_minimum_required(VERSION 3.2)

project(afl-dyn)

### Need to be Set
set(DYNINST_ROOT "/usr/local/lib")
set(DYNINST_BUILD "/home/vigi/dyninst-10.1.0/build")
set(DYNINST_VER10 ON)
set(AFL_ROOT "/home/vigi/afl-2.52b")
###

set(CURRENT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(CURRENT_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR})

set(CMAKE_C_FLAGS "-Wall -pedantic -g -std=gnu99")
set(CMAKE_CXX_FLAGS "-Wall -O3 -std=c++11 -g")

set(DYNINST9_FLAGS "-lcommon -liberty")
set(DYNINST10_FLAGS "-lboost_system -ltbb -Wl,-rpath ${DYNINST_BUILD}/tbb/src/tbb_release")


if(DYNINST_VER10)
    include_directories(${DYNINST_BUILD}/tbb/src/TBB/src/include)
    link_directories(${DYNINST_BUILD}/tbb/src/tbb_release)
    set(DYNINST_OPT ${DYNINST10_FLAGS})
else()
    set(DYNINST_OPT ${DYNINST9_FLAGS})
endif()

include_directories(${AFL_ROOT})
include_directories(${DYNINST_ROOT}/include)
link_directories(${DYNINST_ROOT}/lib)
set(DYNINST_FLAGS "-ldyninstAPI -lboost_system")
set(AFL_STUB_FLAGS "-fpic")

add_library(afl-stub SHARED afl-stub.cc)
target_compile_options(afl-stub
                       PRIVATE ${DYNINST_OPT})
set_property(TARGET afl-stub
             PROPERTY LINK_FLAGS ${AFL_STUB_FLAGS})

add_executable(afl-dyninst afl-dyninst.cc)
target_compile_options(afl-dyninst
                       PRIVATE ${DYNINST_OPT})
set_property(TARGET afl-dyninst
             PROPERTY LINK_FLAGS ${DYNINST_FLAGS})

