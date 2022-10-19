# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_unit_test(unit_tests unit_tests.cpp --data-dir ${CMAKE_CURRENT_SOURCE_DIR}/test-data)
