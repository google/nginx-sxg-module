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

#ifndef NGX_SXG_UTILS_H_
#define NGX_SXG_UTILS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __USE_THIRD_PARTY__
#include "third_party/openssl/evp.h"
#else
#include "openssl/evp.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Get minimum length before delimiter, but delimiters quoted between quotes[0]
// and quotes[1] will be ignored.
size_t get_term_length(const char* str, size_t len, char delimiter,
                       const char quotes[2]);

// Decides response should be SXG or not from HTTP accept header.
// e.g. application/signed-exchange;q=0.9;v=b3,text/html;q=0.8 -> true
bool highest_qvalue_is_sxg(const char* param, size_t len);

// Detects rel="preload" parameter in HTTP link header.
// e.g. rel="foo preload bar" -> true
bool param_is_preload(const char* param, size_t len);

// Loads and create EVP_PKEY struct from private key filepath.
EVP_PKEY* load_private_key(const char* filepath);

// Loads and create X509 struct from certs filepath.
X509* load_x509_cert(const char* filepath);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // NGX_SXG_UTILS_H_
