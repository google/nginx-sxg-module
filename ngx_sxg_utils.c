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
#include <stdio.h>
#include <string.h>
#include <strings.h>

#ifdef __USE_THIRD_PARTY__
#include "third_party/openssl/pem.h"
#else
#include "openssl/pem.h"
#endif

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

bool highest_qvalue_is_sxg(const char* str, size_t len) {
  int max_priority = 0;
  bool should_be_sxg = false;
  for (const char* const end = str + len; str < end;) {
    const size_t tail = get_term_length(str, len, ',', "<>");
    const bool is_sxg = term_is_sxg(str, tail);
    const int p = get_priority(str, tail);
    if (max_priority < p) {
      should_be_sxg = is_sxg;
      max_priority = p;
    }
    str += tail + 1;
    len -= tail + 1;
  }
  return should_be_sxg;
}

// Finds |desired| word exists in quoted and space-separated string.
// The |desired| word must not contain space.
// |desired| must be null terminated.
static bool quoted_string_match(const char* str, size_t len,
                                const char* desired) {
  if (str[0] != '"' || str[len - 1] != '"') {
    return false;
  }
  ++str;     // Skip '"'.
  len -= 2;  // Omit first and last '"'.
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
  static const char kRel[] = "rel=";
  static const char kPreload[] = "preload";
  if (len < sizeof(kRel) - 1 ||
      strncmp((char*)param, kRel, sizeof(kRel) - 1) != 0) {
    return false;
  }
  param += sizeof(kRel) - 1;
  len -= sizeof(kRel) - 1;
  if (len > 0 && *param == '"') {
    return quoted_string_match(param, len, kPreload);
  } else {
    return len == sizeof(kPreload) - 1 && memcmp(param, kPreload, len) == 0;
  }
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
