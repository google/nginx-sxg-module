# Copyright 2019 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

project (sxg LANGUAGES C CXX)
cmake_minimum_required (VERSION 3.0)

set (CMAKE_PROJECT_VERSION "0")
set (CMAKE_PROJECT_VERSION_MAJOR "0")
set (CMAKE_PROJECT_VERSION_MINOR "1")
set (CMAKE_PROJECT_VERSION_PATCH "0")

set (CMAKE_CXX_FLAGS
     "${CMAKE_CXX_FLAGS} -Wall -Wextra -std=c++11 -fPIC -g -ggdb")
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -std=c99 -fPIC -g -ggdb")

set_property (DIRECTORY ${PROJECT_SOURCE_DIR} PROPERTY EP_UPDATE_DISCONNECTED 1)

find_package (OpenSSL REQUIRED)
find_library (LIBSXG NAMES sxg)

add_library (ngx_sxg_utils SHARED ngx_sxg_utils.c)
include_directories(/home/twifkak/usr/include)
target_link_libraries (ngx_sxg_utils PRIVATE ${LIBSXG} ${OPENSSL_LIBRARIES})

# This target requires cmake-format executable in your path.
add_custom_target (
  cmake_format
  COMMAND cmake-format -i ${CMAKE_SOURCE_DIR}/CMakeLists.txt
  COMMENT "Formating with cmake-format ...")

enable_testing ()

file (COPY testdata DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

include (ExternalProject)
ExternalProject_Add (
  googletest
  GIT_REPOSITORY https://github.com/google/googletest
  GIT_TAG master
  SOURCE_DIR ${PROJECT_BINARY_DIR}/third_party/gtest
  BINARY_DIR ${PROJECT_BINARY_DIR}/gtest
  INSTALL_COMMAND "")

add_library (gtest IMPORTED STATIC GLOBAL)
add_dependencies (gtest googletest)
set (GTEST_INCLUDE_DIR
     "${PROJECT_BINARY_DIR}/third_party/gtest/googletest/include")
file (MAKE_DIRECTORY "${GTEST_INCLUDE_DIR}")

set_target_properties (
  gtest
  PROPERTIES IMPORTED_LOCATION "${PROJECT_BINARY_DIR}/gtest/lib/libgtest.a"
             IMPORTED_LINK_INTERFACE_LIBRARIES "${CMAKE_THREAD_LIBS_INIT}"
             INTERFACE_INCLUDE_DIRECTORIES "${GTEST_INCLUDE_DIR}")

add_library (libgtest_main IMPORTED STATIC GLOBAL)
add_dependencies (libgtest_main gtest)
set_target_properties (
  libgtest_main
  PROPERTIES IMPORTED_LOCATION "${PROJECT_BINARY_DIR}/gtest/lib/libgtest_main.a"

             IMPORTED_LINK_INTERFACE_LIBRARIES "${CMAKE_THREAD_LIBS_INIT}")
target_link_libraries (gtest INTERFACE pthread libgtest_main)

macro (add_test_macro target_name test_name)
  add_executable (${target_name} ${test_name}.cc)
  add_test (NAME ${target_name} COMMAND ${target_name})
  add_dependencies (${target_name} gtest ngx_sxg_utils)
  target_link_libraries (${target_name} PRIVATE gtest ngx_sxg_utils)
endmacro ()

function (configure_test test_name)
  message ("-- Configuring test: ${test_name}")
  add_test_macro (${test_name} ${test_name})
endfunction ()

configure_test (ngx_sxg_utils_test)
