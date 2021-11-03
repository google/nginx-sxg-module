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
#include "third_party/openssl/ocsp.h"
#else
#include "openssl/evp.h"
#include "openssl/ocsp.h"
#endif
#include "libsxg.h"

#ifdef __cplusplus
extern "C" {
#endif

// Not thread-safe. Callers are responsible for protecting multithreaded
// access, including via any of the below functions.
typedef struct {
  sxg_buffer_t serialized_cert_chain;
  X509* certificate;
  X509* issuer;
  OCSP_RESPONSE* ocsp;
} ngx_sxg_cert_chain_t;

// Gets minimum length before delimiter, but delimiters quoted between quotes[0]
// and quotes[1] will be ignored.
size_t get_term_length(const char* str, size_t len, char delimiter,
                       const char quotes[2]);

// Decides response should be SXG or not from HTTP accept header.
// e.g. application/signed-exchange;v=b3,text/html;q=0.8 -> true
bool sxg_qvalue_is_1(const char* param, size_t len);

// Detects rel="preload" parameter in HTTP link header.
// e.g. rel="foo preload bar" -> true
bool param_is_preload(const char* param, size_t len);

// Detects as="*" parameter in HTTP link header.
// e.g. as="image" -> true
bool param_is_as(const char* param, size_t len, const char** value,
                 size_t* value_len);

// Loads and create EVP_PKEY struct from private key filepath.
EVP_PKEY* load_private_key(const char* filepath);

// Loads and create X509 struct from certs filepath.
X509* load_x509_cert(const char* filepath);

// Returns empty ngx_sxg_cert_chain_t.
ngx_sxg_cert_chain_t ngx_sxg_empty_cert_chain();

// Release ngx_sxg_empty_cert_chain_t.
void ngx_sxg_cert_chain_release(ngx_sxg_cert_chain_t* target);

// Loads certificates for Certificate-Chain type.
bool load_cert_chain(const char* cert_path, ngx_sxg_cert_chain_t* target);

// Loads and serialize Cert-Chain to `dst`.
bool write_cert_chain(const ngx_sxg_cert_chain_t* cert, sxg_buffer_t* dst);

// Checks and refreshes the OCSP response. Returns true if refresh done.
// Returns false if refresh is not required.
bool refresh_if_needed(ngx_sxg_cert_chain_t* target);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // NGX_SXG_UTILS_H_
