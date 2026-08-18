# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
cmake_minimum_required(VERSION 3.16)

project(didx509cpp LANGUAGES CXX C ASM)

set(CMAKE_CXX_STANDARD 20)

option(PROFILE "enable profiling" OFF)
option(TESTS "enable testing" ON)
option(CLANG_TIDY "run clang-tidy on the codebase" OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library(didx509cpp INTERFACE)
target_include_directories(didx509cpp INTERFACE .)

install(TARGETS didx509cpp)

set(CMAKE_FIND_LIBRARY_SUFFIXES ".a" ".so")

find_package(OpenSSL)
target_compile_definitions(didx509cpp INTERFACE HAVE_OPENSSL)
target_link_libraries(didx509cpp INTERFACE crypto)

if(CLANG_TIDY)
  find_program(
    CLANG_TIDY_EXE
    NAMES clang-tidy-18 clang-tidy
  )
  if(NOT CLANG_TIDY_EXE)
    message(FATAL_ERROR "CLANG_TIDY is ON, but clang-tidy was not found")
  endif()

  message(STATUS "Using clang-tidy from: ${CLANG_TIDY_EXE}")

  function(enable_clang_tidy TARGET)
    set_property(
      TARGET ${TARGET}
      PROPERTY CXX_CLANG_TIDY "${CLANG_TIDY_EXE}"
    )
  endfunction()

  # Compile a minimal translation unit so clang-tidy can check this header-only
  # library without reporting findings from the unit test implementation.
  add_library(clang-tidy-library OBJECT test/clang_tidy.cpp)
  target_link_libraries(clang-tidy-library PRIVATE didx509cpp)
  enable_clang_tidy(clang-tidy-library)
  add_custom_target(clang-tidy DEPENDS clang-tidy-library)
endif()

if(TESTS)
  enable_testing()

  function(add_unit_test NAME SRC)
    add_executable(${NAME} ${SRC})
    target_link_libraries(${NAME} PRIVATE $<BUILD_INTERFACE:didx509cpp>)

    if(CLANG_TIDY)
      enable_clang_tidy(${NAME})
      add_dependencies(clang-tidy ${NAME})
    endif()

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
