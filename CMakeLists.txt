# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
cmake_minimum_required(VERSION 3.16)

project(didx509cpp LANGUAGES CXX C ASM)

set(CMAKE_CXX_STANDARD 20)

option(PROFILE "enable profiling" OFF)
option(TESTS "enable testing" ON)

add_library(didx509cpp INTERFACE)
target_include_directories(didx509cpp INTERFACE .)

install(TARGETS didx509cpp)

set(CMAKE_FIND_LIBRARY_SUFFIXES ".a" ".so")

find_package(OpenSSL)
target_compile_definitions(didx509cpp INTERFACE HAVE_OPENSSL)
target_link_libraries(didx509cpp INTERFACE crypto)

if(TESTS)
  enable_testing()

  function(add_unit_test NAME SRC)
    add_executable(${NAME} ${SRC})
    target_link_libraries(${NAME} PRIVATE $<BUILD_INTERFACE:didx509cpp>)

    if(PROFILE)
      target_compile_options(${NAME} PRIVATE -g -pg)
      target_link_options(${NAME} PRIVATE -g -pg)
    endif()

    if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
      target_compile_options(
        ${NAME} PRIVATE -fsanitize=undefined,address,leak -fno-omit-frame-pointer
      )
      target_link_options(${NAME} PRIVATE -fsanitize=undefined,address,leak)
    endif()

    add_test(NAME ${NAME} COMMAND ${NAME} ${ARGN})
  endfunction()

  add_subdirectory(test)
endif()
