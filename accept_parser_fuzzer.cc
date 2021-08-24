// Copyright 2019 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

// Run with:
// clang -g -O1 -Lbuild -lngx_sxg_utils -fsanitize=fuzzer,address,undefined \
//   accept_parser_fuzzer.cc &&
//   LD_LIBRARY_PATH=build ./a.out -dict=accept_parser_dict.txt

#include "ngx_sxg_utils.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  sxg_qvalue_is_1(reinterpret_cast<const char *>(data), size);
  return 0;
}
