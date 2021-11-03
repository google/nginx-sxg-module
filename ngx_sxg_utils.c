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

#include "ngx_sxg_utils.h"

#include <ctype.h>
#include <ngx_core.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#ifdef __USE_THIRD_PARTY__
#include "third_party/openssl/ocsp.h"
#include "third_party/openssl/pem.h"
#else
#include "openssl/ocsp.h"
#include "openssl/pem.h"
#endif

#include "libsxg.h"

size_t get_term_length(const char* str, size_t len, char delimiter,
                       const char quotes[2]) {
  bool inside_quote = false;
  for (size_t i = 0; i < len; ++i) {
    if (!inside_quote) {
      if (str[i] == quotes[0]) {
        inside_quote = true;
      } else if (str[i] == delimiter) {
        return i;
      }
    } else if (inside_quote && str[i] == quotes[1]) {
      inside_quote = false;
    }
  }
  return len;
}

// Returns value pointer for spefified |key|. Skips prefix whitespace or tab.
// |key| is case insensitive.
static const char* extract_prefix_with_whitespace(const char* key,
                                                  const char* str,
                                                  size_t strlength) {
  if (strlength == 0) {
    return NULL;
  }
  const size_t keylength = strlen(key);
  // Omit optional white space prefix.
  while (strlength > 0 && (*str == ' ' || *str == '\t')) {
    ++str;
    --strlength;
  }
  if (keylength <= strlength && strncasecmp(key, str, keylength) == 0) {
    return str + keylength;
  }
  return NULL;
}

// Returns true if the first word of |str| equals |expected| after optional
// double-quotation is removed. Whitespace means end of value.
static bool first_word_match(const char* expected, const char* str,
                             size_t len) {
  const size_t expected_length = strlen(expected);
  if (len == 0 || (str[0] == '"' && len == 1)) {
    return false;
  }
  if (str[0] == '"' && str[len - 1] == '"') {
    str += 1;
    len -= 2;
  }
  if (len < expected_length) {
    return false;
  }
  return strncmp(str, expected, expected_length) == 0 &&
         (len == expected_length || str[expected_length] == ' ');
}

static bool term_is_sxg(const char* str, size_t len) {
  static const char kSxg[] = "application/signed-exchange";
  static const char kValueKey[] = "v=";
  static const char kValidVersion[] = "b3";
  const char* const end = str + len;
  const size_t media_range_tail = get_term_length(str, len, ';', "<>");
  if (len < strlen(kSxg) || strncmp(kSxg, str, strlen(kSxg)) != 0 ||
      len == media_range_tail) {  // The version information is missing.
    return false;
  }
  str += media_range_tail + 1;
  while (str < end) {
    const size_t tail = get_term_length(str, end - str, ';', "\"\"");
    const char* const value_ptr =
        extract_prefix_with_whitespace(kValueKey, str, tail);
    if (value_ptr != NULL) {
      return first_word_match(kValidVersion, value_ptr,
                              tail - (value_ptr - str));
    }
    str += tail + 1;
  }
  return false;
}

// Returns qvalue * 1000.
// Returns 0 if qvalue does not match the RFC7231 spec.
static int parse_qvalue(const char* str, size_t len) {
  // https://tools.ietf.org/html/rfc7231#section-5.3.1 says that
  // qvalue MUST be between 0.000 and 1.000.
  while (len > 0 && (str[len - 1] == ' ' || str[len - 1] == '\t')) {
    --len;
  }
  if (len == 1 && *str == '1') {
    return 1000;
  }
  if (len == 0 || len > 5) {  // Contains no digits or extra digits.
    return 0;
  }
  char data[6] = {};  // 1 digit + '.' + 3 digits + null
  memcpy(data, str, len);
  if (strspn(data, "1234567890.") != len) {  // Contains non-digit word.
    return 0;
  }
  memset(data + len, '0', sizeof(data) - len - 1);
  int whole = 0, part = 0;
  if (sscanf(data, "%d.%d", &whole, &part) != 2) {
    return 0;
  }
  int qvalue = whole * 1000 + part;
  return qvalue > 0 && qvalue <= 1000 ? qvalue : 0;
}

// Find and return qvalue.
// e.g. text/html;q=0.8 -> 800
//      image/png; -> 1000 (Omittion means MAX)
static int get_priority(const char* str, size_t len) {
  for (;;) {
    const size_t tail = get_term_length(str, len, ';', "\"\"");
    const char* value_ptr = extract_prefix_with_whitespace("q=", str, tail);
    if (value_ptr != NULL) {
      return parse_qvalue(value_ptr, tail - (value_ptr - str));
    }
    str += tail;
    len -= tail;
    if (len == 0) {
      break;
    }
    ++str;
    --len;
  }
  return 1000;
}

bool sxg_qvalue_is_1(const char* str, size_t len) {
  for (const char* const end = str + len; str < end;) {
    const size_t tail = get_term_length(str, len, ',', "<>");
    if (term_is_sxg(str, tail) && get_priority(str, tail) == 1000) {
      return true;
    }
    str += tail + 1;
    len -= tail + 1;
  }
  return false;
}

// Truncates optional white spaces at head and tail.
static void strip(const char** str, size_t* len) {
  while (*len > 0 && (**str == ' ' || **str == '\t')) {
    ++*str;
    --*len;
  }
  while (*len > 0 && ((*str)[*len - 1] == ' ' || (*str)[*len - 1] == '\t')) {
    --*len;
  }
}

// Finds |desired| word exists in quoted and space-separated string.
// The |desired| word must not contain space.
// |desired| must be null terminated.
static bool quoted_string_match(const char* str, size_t len,
                                const char* desired) {
  if (len < 2 || str[0] != '"' || str[len - 1] != '"') {
    return false;
  }
  ++str;     // Skip '"'.
  len -= 2;  // Omit first and last '"'.
  strip(&str, &len);
  const size_t desired_length = strlen(desired);
  const char* const end = str + len;
  while (str < end) {
    size_t tail = get_term_length(str, len, ' ', "<>");
    if (tail == desired_length && memcmp(str, desired, desired_length) == 0) {
      return true;
    }
    str += tail + 1;
    len -= tail + 1;
  }
  return false;
}

bool param_is_preload(const char* param, size_t len) {
  strip(&param, &len);
  static const char kRel[] = "rel";
  static const char kPreload[] = "preload";

  if (len < sizeof(kRel) - 1 ||
      memcmp((char*)param, kRel, sizeof(kRel) - 1) != 0) {
    return false;
  }
  param += sizeof(kRel) - 1;
  len -= sizeof(kRel) - 1;
  strip(&param, &len);

  if (len < sizeof(kPreload) || param[0] != '=') {
    return false;
  }
  param++;
  len--;
  strip(&param, &len);

  return quoted_string_match(param, len, kPreload) ||
         (len == sizeof(kPreload) - 1 && memcmp(param, kPreload, len) == 0);
}

bool param_is_as(const char* param, size_t len, const char** value,
                 size_t* value_len) {
  strip(&param, &len);
  static const char kAs[] = "as";
  *value = NULL;
  *value_len = 0;

  if (len < sizeof(kAs) - 1 ||
      memcmp((char*)param, kAs, sizeof(kAs) - 1) != 0) {
    return false;
  }
  param += sizeof(kAs) - 1;
  len -= sizeof(kAs) - 1;
  strip(&param, &len);

  if (len == 0 || param[0] != '=') {
    return false;
  }
  param++;
  len--;
  strip(&param, &len);

  if (len > 0 && *param == '"') {
    const char* end = strchr(param + 1, '"');
    if (end == NULL) {
      return false;
    }
    param += 1;
    len = end - param;
    strip(&param, &len);
  }
  *value = param;
  *value_len = len;

  return len > 0;
}

EVP_PKEY* load_private_key(const char* filepath) {
  FILE* const fp = fopen(filepath, "r");
  if (!fp) {
    return NULL;
  }
  EVP_PKEY* private_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
  fclose(fp);
  return private_key;
}

X509* load_x509_cert(const char* filepath) {
  FILE* certfile = fopen(filepath, "r");
  if (!certfile) {
    return NULL;
  }
  char passwd = 0;
  X509* cert = PEM_read_X509(certfile, 0, 0, &passwd);
  fclose(certfile);
  return cert;
}

ngx_sxg_cert_chain_t ngx_sxg_empty_cert_chain() {
  static ngx_sxg_cert_chain_t empty;
  empty.serialized_cert_chain = sxg_empty_buffer();
  empty.certificate = NULL;
  empty.issuer = NULL;
  empty.ocsp = NULL;
  return empty;
}

void ngx_sxg_cert_chain_release(ngx_sxg_cert_chain_t* target) {
  sxg_buffer_release(&target->serialized_cert_chain);
  if (target->certificate != NULL) {
    X509_free(target->certificate);
    target->certificate = NULL;
  }
  if (target->issuer != NULL) {
    X509_free(target->issuer);
    target->issuer = NULL;
  }
}

bool load_cert_chain(const char* cert_path, ngx_sxg_cert_chain_t* target) {
  FILE* certfile = fopen(cert_path, "r");
  if (!certfile) {
    return false;
  }
  char passwd = 0;
  X509* cert = PEM_read_X509(certfile, 0, 0, &passwd);
  X509* issuer = PEM_read_X509(certfile, 0, 0, &passwd);
  fclose(certfile);

  target->certificate = cert;
  target->issuer = issuer;
  return cert != NULL && issuer != NULL;
}

bool write_cert_chain(const ngx_sxg_cert_chain_t* cert, sxg_buffer_t* dst) {
  sxg_buffer_t empty_sct_list = sxg_empty_buffer();
  sxg_cert_chain_t chain = sxg_empty_cert_chain();
  bool success =
      sxg_cert_chain_append_cert(cert->certificate, cert->ocsp, &empty_sct_list,
                                 &chain) &&
      sxg_cert_chain_append_cert(cert->issuer, NULL, &empty_sct_list, &chain) &&
      sxg_write_cert_chain_cbor(&chain, dst);
  // Don't call sxg_cert_chain_release, as it would also free
  // cert->certificate, cert->ocsp, and cert->issuer.
  if (chain.certs != NULL) {
    OPENSSL_free(chain.certs);
  }
  sxg_buffer_release(&empty_sct_list);
  return success;
}

static bool asn1_generalizedtime_to_unixtime(const ASN1_GENERALIZEDTIME* ag,
                                             time_t* out) {
  if (ag->type != V_ASN1_GENERALIZEDTIME) {
    return false;
  }
  struct tm t;
  if (ASN1_TIME_to_tm(ag, &t) != 1) {
    return false;
  }
  *out = mktime(&t);
  return true;
}

static bool check_refresh_needed(ngx_sxg_cert_chain_t* target) {
  if (target->ocsp == NULL) {
    return true;
  }
  OCSP_BASICRESP* br = OCSP_response_get1_basic(target->ocsp);
  const int resps = OCSP_resp_count(br);
  for (int i = 0; i < resps; ++i) {
    OCSP_SINGLERESP* leaf = OCSP_resp_get0(br, i);
    ASN1_GENERALIZEDTIME* this_update;
    ASN1_GENERALIZEDTIME* next_update;

    int status = OCSP_single_get0_status(leaf, /*revocation_reason=*/NULL,
                                         /*revocation_time=*/NULL, &this_update,
                                         &next_update);
    if (status == -1) {
      return true;
    }

    time_t since;
    time_t until;
    if (!asn1_generalizedtime_to_unixtime(this_update, &since) ||
        !asn1_generalizedtime_to_unixtime(next_update, &until)) {
      return true;
    }

    if (since >= until) {
      // Unexpected error in the OCSP response; refresh immediately.
      return true;
    }
    time_t middle_lifespan = since + ((until - since) / 2);
    const time_t now = time(NULL);

    if (middle_lifespan < now) {
      return true;
    }
  }
  return false;
}

bool refresh_if_needed(ngx_sxg_cert_chain_t* target) {
  if (!check_refresh_needed(target)) {
    return false;
  }
  if (target->ocsp != NULL) {
    OCSP_RESPONSE_free(target->ocsp);
  }
  sxg_buffer_resize(0, &target->serialized_cert_chain);
  return sxg_fetch_ocsp_response(target->certificate, target->issuer,
                                 &target->ocsp) &&
         write_cert_chain(target, &target->serialized_cert_chain);
}
