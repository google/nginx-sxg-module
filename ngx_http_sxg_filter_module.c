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

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <pthread.h>
#include <stdbool.h>

#include "libsxg.h"
#include "ngx_sxg_utils.h"

#ifdef BLAZE
#include "third_party/openssl/pem.h"
#else
#include "openssl/pem.h"
#endif

typedef struct {
  ngx_flag_t enable;
  size_t sxg_max_payload;
  ngx_str_t certificate;
  ngx_str_t certificate_key;
  ngx_str_t cert_url;
  ngx_str_t validity_url;
  ngx_str_t cert_path;
  time_t expiry_seconds;
  ngx_str_t fallback_host;
  sxg_signer_list_t signers;

  // Protected by cert_chain_lock;
  ngx_sxg_cert_chain_t cert_chain;
  pthread_mutex_t cert_chain_lock;
} ngx_http_sxg_loc_conf_t;

typedef struct {
  ngx_str_t url;
  ngx_str_t as;
} ngx_subresource_t;

// A context structure which is allocated for every single client request.
// This structure will be concurrently accessed to handle multiple subrequest
// handling.
typedef struct {
  int subresources;
  int main_resource_loaded;
  sxg_raw_response_t response;
  ngx_http_sxg_loc_conf_t* loc_conf;
  bool cert_chain_mode;
  ngx_str_t link_header;
  ngx_array_t subresource_list;

  // On accessing members, first you should get this lock.
  pthread_mutex_t lock;
} ngx_http_sxg_ctx_t;

static ngx_http_output_header_filter_pt ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt ngx_http_next_body_filter;
static ngx_int_t ngx_http_sxg_filter_init(ngx_conf_t* cf);
static void* ngx_http_sxg_create_loc_conf(ngx_conf_t* cf);
static char* ngx_http_sxg_merge_loc_conf(ngx_conf_t* cf, void* parent,
                                         void* child);
static char* construct_fallback_url(const ngx_http_request_t* r,
                                    ngx_str_t* fallback_host);
static ngx_int_t subresource_fetch_handler_impl(ngx_http_request_t* req,
                                                ngx_http_core_srv_conf_t* cscf,
                                                ngx_http_sxg_ctx_t* ctx);
static ngx_int_t ngx_http_sxg_body_filter_impl(ngx_http_request_t* req,
                                               ngx_http_sxg_ctx_t* ctx,
                                               ngx_chain_t* in);
static bool is_valid_config(ngx_conf_t* nc, const ngx_http_sxg_loc_conf_t* sc);

static ngx_command_t ngx_http_sxg_commands[] = {
    {ngx_string("sxg"), NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_sxg_loc_conf_t, enable), NULL},
    {ngx_string("sxg_max_payload"), NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_size_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_sxg_loc_conf_t, sxg_max_payload), NULL},
    {ngx_string("sxg_certificate"), NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_sxg_loc_conf_t, certificate), NULL},
    {ngx_string("sxg_certificate_key"), NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_sxg_loc_conf_t, certificate_key), NULL},
    {ngx_string("sxg_cert_url"), NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_sxg_loc_conf_t, cert_url), NULL},
    {ngx_string("sxg_validity_url"), NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_sxg_loc_conf_t, validity_url), NULL},
    {ngx_string("sxg_cert_path"), NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_sxg_loc_conf_t, cert_path), NULL},
    {ngx_string("sxg_expiry_seconds"), NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_sec_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_sxg_loc_conf_t, expiry_seconds), NULL},
    {ngx_string("sxg_fallback_host"), NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_sxg_loc_conf_t, fallback_host), NULL},
    ngx_null_command};

static ngx_http_module_t ngx_http_sxg_filter_module_ctx = {
    NULL,                     /* preconfiguration */
    ngx_http_sxg_filter_init, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    ngx_http_sxg_create_loc_conf, /* create location configuration */
    ngx_http_sxg_merge_loc_conf,  /* merge location configuration */
};

ngx_module_t ngx_http_sxg_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_sxg_filter_module_ctx, /* module context */
    ngx_http_sxg_commands,           /* module directives */
    NGX_HTTP_MODULE,                 /* module type */
    NULL,                            /* init master */
    NULL,                            /* init module */
    NULL,                            /* init process */
    NULL,                            /* init thread */
    NULL,                            /* exit thread */
    NULL,                            /* exit process */
    NULL,                            /* exit master */
    NGX_MODULE_V1_PADDING            /* padding */
};

static char* str_to_null_terminated(ngx_pool_t* pool, const ngx_str_t* str) {
  char* copied = ngx_palloc(pool, str->len + 1);
  if (copied == NULL) {
    return NULL;
  }
  memcpy(copied, str->data, str->len);
  copied[str->len] = '\0';
  return copied;
}

static void ngx_http_sxg_free_loc_conf(void* data) {
  ngx_http_sxg_loc_conf_t* slc = data;
  pthread_mutex_destroy(&slc->cert_chain_lock);
}

static void* ngx_http_sxg_create_loc_conf(ngx_conf_t* cf) {
  ngx_pool_cleanup_t* cleanup =
      ngx_pool_cleanup_add(cf->pool, sizeof(ngx_http_sxg_loc_conf_t));
  cleanup->handler = ngx_http_sxg_free_loc_conf;

  ngx_http_sxg_loc_conf_t* slc = cleanup->data;
  slc->enable = NGX_CONF_UNSET;
  slc->sxg_max_payload = NGX_CONF_UNSET_SIZE;
  slc->certificate = (ngx_str_t){.data = NULL, .len = 0};
  slc->certificate_key = (ngx_str_t){.data = NULL, .len = 0};
  slc->cert_url = (ngx_str_t){.data = NULL, .len = 0};
  slc->validity_url = (ngx_str_t){.data = NULL, .len = 0};
  slc->cert_path = (ngx_str_t){.data = NULL, .len = 0};
  slc->expiry_seconds = NGX_CONF_UNSET;
  slc->fallback_host = (ngx_str_t){.data = NULL, .len = 0};
  slc->signers = sxg_empty_signer_list();
  slc->cert_chain = ngx_sxg_empty_cert_chain();
  if (pthread_mutex_init(&slc->cert_chain_lock, NULL) != 0) {
    ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                  "nginx-sxg-module: failed to initialize cert_chain_lock");
  }
  return slc;
}

static char* ngx_http_sxg_merge_loc_conf(ngx_conf_t* cf, void* parent,
                                         void* child) {
  ngx_http_sxg_loc_conf_t* prev = parent;
  ngx_http_sxg_loc_conf_t* conf = child;
  ngx_conf_merge_value(conf->enable, prev->enable, 0);
  ngx_conf_merge_size_value(conf->sxg_max_payload, prev->sxg_max_payload,
                            64 * 1024 * 1024);  // Limited to 64 MB
  ngx_conf_merge_str_value(conf->certificate, prev->certificate, "");
  ngx_conf_merge_str_value(conf->certificate_key, prev->certificate_key, "");
  ngx_conf_merge_str_value(conf->cert_url, prev->cert_url, "");
  ngx_conf_merge_str_value(conf->validity_url, prev->validity_url, "");
  ngx_conf_merge_str_value(conf->cert_path, prev->cert_path, "");
  ngx_conf_merge_sec_value(conf->expiry_seconds, prev->expiry_seconds,
                           60 * 60 * 24);  // 1 day.
  ngx_conf_merge_str_value(conf->fallback_host, prev->fallback_host, "");

  if (!is_valid_config(cf, conf)) {
    if (conf->enable) {
      return NGX_CONF_ERROR;
    } else {
      return NGX_OK;
    }
  }

  bool loaded = false;
  if (prev->signers.size > 0) {
    conf->signers = prev->signers;
  } else {
    EVP_PKEY* privkey =
        load_private_key((const char*)conf->certificate_key.data);
    if (privkey == NULL) {
      ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                    "nginx-sxg-module: failed to load private key at %V",
                    &conf->certificate_key);
      return NGX_CONF_ERROR;
    }
    X509* cert = load_x509_cert((const char*)conf->certificate.data);
    if (cert == NULL) {
      ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                    "nginx-sxg-module: failed to load certificate at %V",
                    &conf->certificate);
      return NGX_CONF_ERROR;
    }
    if (!sxg_add_ecdsa_signer("nginx", /*date=*/0, /*expires=*/0,
                              (const char*)conf->validity_url.data, privkey,
                              cert, (const char*)conf->cert_url.data,
                              &conf->signers)) {
      ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                    "nginx-sxg-module: failed to allocate memory");
      return NGX_CONF_ERROR;
    }
    loaded = true;
    EVP_PKEY_free(privkey);
    X509_free(cert);
  }

  if (pthread_mutex_lock(&prev->cert_chain_lock) != 0) {
    ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                  "nginx-sxg-module: Failed to acquire cert_chain_lock");
    return NGX_CONF_ERROR;
  }
  if (pthread_mutex_lock(&conf->cert_chain_lock) != 0) {
    // NOTE: If the following unlock fails, it leaves prev->cert_chain_lock in
    // a permanently locked state. I'm not sure if that's a problem in
    // practice, given NGX_LOG_EMERG and NGX_CONF_ERROR.
    pthread_mutex_unlock(&prev->cert_chain_lock);
    ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                  "nginx-sxg-module: Failed to acquire cert_chain_lock");
    return NGX_CONF_ERROR;
  }
  if (prev->cert_chain.certificate != NULL && prev->cert_chain.issuer != NULL) {
    conf->cert_chain = prev->cert_chain;
  } else {
    if (conf->cert_path.len > 0 &&
        !load_cert_chain((const char*)conf->certificate.data,
                         &conf->cert_chain)) {
      ngx_log_error(
          NGX_LOG_EMERG, cf->log, 0,
          "nginx-sxg-module: failed to load Cert-Chain at %V (sxg_cert_path "
          "cannot be used if you are using a self-signed certificate)",
          &conf->certificate);
      return NGX_CONF_ERROR;
    }
  }
  if (pthread_mutex_unlock(&conf->cert_chain_lock) != 0 ||
      pthread_mutex_unlock(&prev->cert_chain_lock) != 0) {
    ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                  "nginx-sxg-module: Failed to release cert_chain_lock");
  }

  if (conf->expiry_seconds > 60 * 60 * 24 * 7) {
    // SXG life-span longer than 7 days is not allowed by spec.
    ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                  "nginx-sxg-module: too long lifespan of SXG %d seconds",
                  conf->expiry_seconds);
    return NGX_CONF_ERROR;
  }

  if (loaded) {
    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                  "nginx-sxg-module: successfully started with below settings\n"
                  "SXG Certificate: %V\n"
                  "SXG PrivateKey: %V\n"
                  "certificate_url: %V\n"
                  "validity_url: %V\n"
                  "cert_path: %V",
                  &conf->certificate, &conf->certificate_key, &conf->cert_url,
                  &conf->validity_url, &conf->cert_path);
  }

  return NGX_OK;
}

static bool response_should_be_sxg(const ngx_http_request_t* const req) {
  static const char kAccept[] = "Accept";

  for (const ngx_list_part_t* part = &req->headers_in.headers.part;
       part != NULL; part = part->next) {
    ngx_table_elt_t* table = part->elts;
    for (unsigned int i = 0; i < part->nelts; ++i) {
      if (table[i].key.len == strlen(kAccept) &&
          strncasecmp((const char*)table[i].key.data, kAccept,
                      table[i].key.len) == 0 &&
          sxg_qvalue_is_1((const char*)table[i].value.data,
                          table[i].value.len)) {
        return true;
      }
    }
  }
  return false;
}

static bool generate_sxg(const ngx_http_request_t* req,
                         const ngx_http_sxg_ctx_t* ctx, sxg_buffer_t* sxg) {
  ngx_http_sxg_loc_conf_t* slc =
      ngx_http_get_module_loc_conf(req, ngx_http_sxg_filter_module);

  // Set parameters.
  sxg_signer_t* const signer = &slc->signers.signers[0];
  signer->date = time(NULL);
  signer->expires = signer->date + slc->expiry_seconds;

  // Generate SXG.
  char* const fallback_url = construct_fallback_url(req, &slc->fallback_host);
  sxg_encoded_response_t content = sxg_empty_encoded_response();
  bool success = fallback_url != NULL &&
                 sxg_encode_response(4096, &ctx->response, &content) &&
                 sxg_generate(fallback_url, &slc->signers, &content, sxg);
  sxg_encoded_response_release(&content);
  ngx_pfree(req->pool, fallback_url);

  return success;
}

static void release_ctx(ngx_pool_t* pool, ngx_http_sxg_ctx_t* ctx) {
  sxg_raw_response_release(&ctx->response);
  pthread_mutex_destroy(&ctx->lock);
}

static bool buffer_write_str_t(const ngx_str_t* str, sxg_buffer_t* target) {
  return sxg_write_bytes(str->data, str->len, target);
}

static bool copy_response_header_to_sxg_header(ngx_pool_t* pool,
                                               const ngx_list_t* headers,
                                               sxg_header_t* header) {
  static const char kExpires[] = "expires";
  for (const ngx_list_part_t* part = &headers->part; part != NULL;
       part = part->next) {
    ngx_table_elt_t* v = part->elts;
    for (size_t i = 0; i < part->nelts; i++) {
      if (strncasecmp(kExpires, (char*)v[i].key.data, strlen(kExpires)) == 0) {
        /* SXG inner header does not require `expires` key */
        continue;
      }

      char* const key = str_to_null_terminated(pool, &v[i].key);
      char* const value = str_to_null_terminated(pool, &v[i].value);
      bool fail = key == NULL || value == NULL ||
                  !sxg_header_append_string(key, value, header);
      ngx_pfree(pool, key);
      ngx_pfree(pool, value);
      if (fail) {
        return false;
      }
    }
  }
  return true;
}

static bool calc_integrity(const ngx_http_request_t* const req,
                           sxg_buffer_t* dst) {
  ngx_http_sxg_loc_conf_t* slc =
      ngx_http_get_module_loc_conf(req, ngx_http_sxg_filter_module);
  sxg_raw_response_t response = sxg_empty_raw_response();
  const ngx_str_t* content_type = &req->headers_out.content_type;
  sxg_encoded_response_t content = sxg_empty_encoded_response();
  const size_t payload_size = req->out->buf->last - req->out->buf->pos;
  if (slc->sxg_max_payload < payload_size) {
    sxg_buffer_release(dst);
    return false;
  }
  bool success =
      copy_response_header_to_sxg_header(req->pool, &req->headers_out.headers,
                                         &response.header) &&
      sxg_header_append_string("content-type", (const char*)content_type->data,
                               &response.header) &&
      sxg_write_bytes(req->out->buf->pos,
                      req->out->buf->last - req->out->buf->pos,
                      &response.payload) &&
      sxg_encode_response(4096, &response, &content) &&
      sxg_write_header_integrity(&content, dst);

  sxg_raw_response_release(&response);
  sxg_encoded_response_release(&content);
  return success;
}

static ngx_int_t subresource_fetch_handler(ngx_http_request_t* req, void* data,
                                           ngx_int_t rc) {
  if (req->done) {
    return NGX_OK;
  }
  ngx_http_core_srv_conf_t* cscf =
      ngx_http_get_module_srv_conf(req, ngx_http_core_module);
  ngx_http_sxg_ctx_t* ctx = data;

  if (ctx == NULL) {
    return NGX_OK;
  }
  if (pthread_mutex_lock(&ctx->lock) != 0) {
    return NGX_ERROR;
  }
  ngx_int_t result = subresource_fetch_handler_impl(req, cscf, ctx);
  if (pthread_mutex_unlock(&ctx->lock) != 0) {
    return NGX_ERROR;
  }

  return result;
}

static ngx_int_t subresource_fetch_handler_impl(ngx_http_request_t* req,
                                                ngx_http_core_srv_conf_t* cscf,
                                                ngx_http_sxg_ctx_t* ctx) {
  if (req->upstream == NULL || req->upstream->headers_in.status_n != 200) {
    // Even if fetching subresource failed, we ignore it.
    --ctx->subresources;
    return NGX_OK;
  }
  if (req->connection->log->log_level >= NGX_LOG_DEBUG) {
    ngx_log_error(NGX_LOG_DEBUG, req->connection->log, 0,
                  "nginx-sxg-module: Subresource fetched. bytes=%l/%l",
                  req->out->buf->last - req->out->buf->pos,
                  req->upstream->length);
    ngx_log_error(NGX_LOG_DEBUG, req->connection->log, 0,
                  "nginx-sxg-module: Subresource uri: %V", &req->uri);
    ngx_log_error(NGX_LOG_DEBUG, req->connection->log, 0,
                  "nginx-sxg-module: Subresource content-type: %V",
                  &req->headers_out.content_type);
    for (ngx_list_part_t* i = &req->headers_out.headers.part; i != NULL;
         i = i->next) {
      for (size_t j = 0; j < i->nelts; ++j) {
        ngx_table_elt_t* elts = i->elts;
        ngx_log_error(NGX_LOG_DEBUG, req->connection->log, 0,
                      "nginx-sxg-module: Subresource %V: %V", &elts[j].key,
                      &elts[j].value);
      }
    }
  }

  // if the request hit the proxy cache, req->upstream->length is -1.
  if (req->out->buf->last - req->out->buf->pos == req->upstream->length ||
      req->upstream->length == -1) {
    ngx_http_set_ctx(req, ctx, ngx_http_sxg_filter_module);
    sxg_buffer_t url = sxg_empty_buffer();

    // Set URL which includes headers and parameters.
    if (!sxg_write_string("https://", &url) ||
        !buffer_write_str_t(&cscf->server_name, &url) ||
        !buffer_write_str_t(&req->uri, &url)) {
      sxg_buffer_release(&url);
      --ctx->subresources;
      return NGX_ERROR;
    }
    if (req->args.len > 0) {  // Append URL parameters.
      if (!sxg_write_string("\?", &url) ||
          !buffer_write_str_t(&req->args, &url)) {
        sxg_buffer_release(&url);
        --ctx->subresources;
        return NGX_ERROR;
      }
    }

    // Search 'as' statement of original link header.
    ngx_str_t as = ngx_null_string;
    ngx_array_t* subresource_list = &ctx->subresource_list;
    ngx_subresource_t* subresource = subresource_list->elts;
    for (size_t i = 0; i < subresource_list->nelts; ++i) {
      if (ngx_strncmp(subresource[i].url.data, req->uri.data,
                      subresource[i].url.len) == 0) {
        as = subresource[i].as;
        break;
      }
    }

    sxg_buffer_t integrity = sxg_empty_buffer();
    sxg_buffer_t new_header_entry = sxg_empty_buffer();
    if (as.len > 0 && sxg_write_string("<", &new_header_entry) &&
        sxg_write_buffer(&url, &new_header_entry) &&
        sxg_write_string(">;rel=\"preload\";as=\"", &new_header_entry) &&
        buffer_write_str_t(&as, &new_header_entry) &&
        sxg_write_string("\",<", &new_header_entry) &&
        sxg_write_buffer(&url, &new_header_entry) &&
        sxg_write_string(">;rel=\"allowed-alt-sxg\";header-integrity=\"",
                         &new_header_entry) &&
        calc_integrity(req, &integrity) &&
        sxg_write_buffer(&integrity, &new_header_entry) &&
        sxg_write_string("\"", &new_header_entry)) {
      sxg_header_append_buffer("link", &new_header_entry,
                               &ctx->response.header);
    }
    sxg_buffer_release(&url);
    sxg_buffer_release(&integrity);
    sxg_buffer_release(&new_header_entry);
    // Even if calculating subresource integrity failed, we ignore it.
    --ctx->subresources;
    return NGX_OK;
  } else {
    return NGX_AGAIN;
  }
}

static ngx_str_t extract_angled_url(char* str, size_t len) {
  char* start = NULL;
  for (char *pos = str, *end = str + len; pos != end; ++pos) {
    if (*pos == '<') {
      start = pos + 1;
    } else if (*pos == '>' && start != NULL) {
      return (ngx_str_t){.data = (u_char*)start, .len = pos - start};
    }
  }
  return (ngx_str_t){.data = NULL, .len = 0};
}

// TODO(kumagi): Complex logic should be migrated to ngx_sxg_utils.c.
// Extracts URL list `dst` from `link` like </foo.js>;rel="preload";as="script"
// Returns length of non-preload header string.
// If `dst` is NULL, it does nothing than calculates and returns the required
// length for `non_preload_headers`.
static size_t extract_preload_url_list(ngx_str_t* link, ngx_array_t* const dst,
                                       ngx_str_t* non_preload_headers,
                                       ngx_http_request_t* r) {
  char* str = (char*)link->data;
  char* end = str + link->len;
  size_t non_preload_headers_len = 0;
  while (str < end) {
    const size_t tail = get_term_length(str, end - str, ',', "<>");
    ngx_str_t url = extract_angled_url(str, tail);
    char* param = str;
    bool found = false;
    ngx_subresource_t* new_preload = NULL;
    ngx_str_t as = ngx_null_string;

    while (param < str + tail) {
      while (*param == ' ' || *param == '\t') {
        ++param;
      }
      const size_t rest = str + tail - param;
      size_t param_tail = get_term_length(param, rest, ';', "<>");
      ngx_str_t param_s = {param_tail, (u_char*)param};
      ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                    "nginx-sxg-module: param is: [%V]", &param_s);

      if (param_is_preload(param, param_tail)) {
        if (dst != NULL) {
          new_preload = ngx_array_push(dst);
          new_preload->url.data = ngx_palloc(r->pool, url.len);
          new_preload->url.len = url.len;
          ngx_memcpy(new_preload->url.data, url.data, url.len);
          while (new_preload->url.data[new_preload->url.len - 1] == ' ') {
            new_preload->url.data[--new_preload->url.len] = '\0';
          }
        }
        found = true;
      }

      if (param_is_as(param, param_tail, (const char**)&as.data, &as.len)) {
        if (found) {
          ngx_log_error(
              NGX_LOG_DEBUG, r->connection->log, 0,
              "nginx-sxg-module: found as statement in link preload header: %V",
              &as);
        }
      }
      param += param_tail + 1;
    }
    if (found) {
      if (new_preload != NULL) {
        new_preload->as = as;
      }
    } else {
      if (non_preload_headers == NULL) {
        if (non_preload_headers_len > 0) {
          ++non_preload_headers_len;
        }
      } else {
        if (non_preload_headers_len > 0) {
          ngx_memcpy(non_preload_headers->data + non_preload_headers_len, ",",
                     1);
          ++non_preload_headers_len;
        }
        ngx_memcpy(non_preload_headers->data + non_preload_headers_len, str,
                   tail);
      }
      non_preload_headers_len += tail;
    }
    str += tail + 1;
  }

  return non_preload_headers_len;
}

static ngx_array_t* get_preload_list(ngx_str_t* link,
                                     ngx_str_t* non_preload_headers,
                                     ngx_http_request_t* req) {
  ngx_array_t* const urls =
      ngx_array_create(req->pool, 1, sizeof(ngx_subresource_t));
  size_t non_preload_headers_len =
      extract_preload_url_list(link, NULL, NULL, req);
  non_preload_headers->data = ngx_palloc(req->pool, non_preload_headers_len);
  non_preload_headers->len = non_preload_headers_len;
  extract_preload_url_list(link, urls, non_preload_headers, req);
  ngx_log_error(NGX_LOG_DEBUG, req->connection->log, 0,
                "nginx-sxg-module: non preload header: %V",
                non_preload_headers);
  return urls;
}

static bool set_str(ngx_pool_t* pool, ngx_str_t* dst, const char* src) {
  const size_t len = strlen(src);
  if (dst->data != NULL) {
    ngx_pfree(pool, dst->data);
  }
  dst->data = ngx_palloc(pool, len);
  if (dst->data == NULL) {
    return false;
  }
  dst->len = len;
  memcpy(dst->data, src, len);
  return true;
}

static bool set_accept_headers(ngx_http_request_t* req, const char* accept) {
  static const char* kAccept = "accept";
  ngx_list_part_t* part = &req->headers_in.headers.part;
  ngx_table_elt_t* v = part->elts;

  for (size_t i = 0; i < part->nelts; i++) {
    if (strncasecmp(kAccept, (const char*)v[i].key.data, strlen(kAccept)) ==
            0 &&
        !set_str(req->pool, &v[i].value, accept)) {
      return false;
    }
  }
  return true;
}

static bool invoke_subrequests(ngx_str_t* link, ngx_http_request_t* req,
                               ngx_http_sxg_ctx_t* ctx) {
  ngx_array_t* urls = get_preload_list(link, &ctx->link_header, req);
  ngx_subresource_t* entry = urls->elts;

  if (!set_accept_headers(req, "*/*")) {
    return false;
  }
  for (size_t i = 0; i < urls->nelts; ++i) {
    ngx_http_request_t* sr = NULL;
    ngx_http_post_subrequest_t* psr =
        ngx_palloc(req->pool, sizeof(ngx_http_post_subrequest_t));
    if (psr == NULL) {
      return false;
    }
    psr->handler = subresource_fetch_handler;
    psr->data = ctx;
    ngx_log_error(NGX_LOG_DEBUG, req->connection->log, 0,
                  "nginx-sxg-module: invoke request for: %V as %V",
                  &entry[i].url, &entry[i].as);

    ngx_int_t rc = ngx_http_subrequest(
        req, &entry[i].url, NULL, &sr, psr,
        NGX_HTTP_SUBREQUEST_WAITED | NGX_HTTP_SUBREQUEST_IN_MEMORY);

    if (rc == NGX_OK) {
      ++ctx->subresources;
    } else {
      return false;
    }
  }
  ctx->subresource_list = *urls;
  return true;
}

static ngx_int_t ngx_http_sxg_header_filter(ngx_http_request_t* req) {
  // Called on every HTTP request.
  ngx_http_sxg_loc_conf_t* slc =
      ngx_http_get_module_loc_conf(req, ngx_http_sxg_filter_module);
  if (!slc->enable) {
    return ngx_http_next_header_filter(req);
  }

  if (slc->cert_path.len > 0 && req->uri.len == slc->cert_path.len &&
      ngx_memcmp(req->uri.data, slc->cert_path.data, req->uri.len) == 0) {
    int rc = ngx_http_send_header(req);
    if (rc == NGX_ERROR || rc > NGX_OK || req->header_only) {
      return rc;
    }
    return NGX_OK;
  }

  if (!response_should_be_sxg(req) || req->header_only ||
      (req->method & NGX_HTTP_HEAD) || req != req->main ||
      req->headers_out.status == NGX_HTTP_NO_CONTENT || req->parent != NULL) {
    return ngx_http_next_header_filter(req);
  }

  ngx_http_sxg_ctx_t* ctx =
      ngx_http_get_module_ctx(req, ngx_http_sxg_filter_module);
  if (ctx == NULL) {
    ctx = ngx_pcalloc(req->pool, sizeof(ngx_http_sxg_ctx_t));
    if (ctx == NULL) {
      return NGX_ERROR;
    }

    if (pthread_mutex_init(&ctx->lock, NULL) != 0) {
      return NGX_ERROR;
    }
    ctx->response = sxg_empty_raw_response();
    ctx->main_resource_loaded = false;
    ngx_http_set_ctx(req, ctx, ngx_http_sxg_filter_module);
  }

  if (pthread_mutex_lock(&ctx->lock) != 0) {
    return NGX_ERROR;
  }

  // Search link header and invoke subrequests.
  static const char kLinkKey[] = "link";
  ngx_str_null(&ctx->link_header);
  for (const ngx_list_part_t* part = &req->headers_out.headers.part;
       part != NULL; part = part->next) {
    ngx_table_elt_t* value = part->elts;
    for (size_t i = 0; i < part->nelts; i++) {
      if (value[i].key.len == strlen(kLinkKey) &&
          ngx_strcasecmp((u_char*)kLinkKey, value[i].key.data) == 0) {
        invoke_subrequests(&value[i].value, req, ctx);

        // Replace outer link header with non-preload headers.
        // TODO(kumagi): Support a case that there are multiple Link headers.
        value[i].value = ctx->link_header;
      }
    }
  }

  ngx_int_t ret = ctx->subresources == 0 ? NGX_OK :  // No more subresources.
                      NGX_AGAIN;  // There are more subresources.
  if (pthread_mutex_unlock(&ctx->lock) != 0) {
    return NGX_ERROR;
  }
  return ret;
}

static char* construct_fallback_url(const ngx_http_request_t* req,
                                    ngx_str_t* fallback_host) {
  static const char kHttpsPrefix[] = "https://";
  const char* host = fallback_host->len > 0
                         ? (const char*)fallback_host->data
                         : (const char*)req->headers_in.host->value.data;
  int fallback_url_length =
      sizeof(kHttpsPrefix) + strlen(host) + req->unparsed_uri.len;
  char* fallback_url = ngx_palloc(req->pool, fallback_url_length + 1);
  if (fallback_url == NULL) {
    return NULL;
  }
  snprintf(fallback_url, fallback_url_length, "%s%s%.*s", kHttpsPrefix, host,
           (int)req->unparsed_uri.len, req->unparsed_uri.data);
  return fallback_url;
}

// Returns true if copied size is under the limit.
// Updates |last_buf_last| if copied buffer includes last_buf.
static bool copy_buffer_to_sxg_buffer(const ngx_http_request_t* req,
                                      const ngx_chain_t* in, sxg_buffer_t* buf,
                                      size_t limit, bool* last_buf) {
  *last_buf = false;
  for (const ngx_chain_t* cl = in; cl != NULL; cl = cl->next) {
    if (cl->buf != NULL) {
      const size_t copy_size = ngx_buf_size(cl->buf);
      if (buf->size + copy_size > limit) {
        ngx_log_error(NGX_LOG_ERR, req->connection->log, 0,
                      "nginx-sxg-module: too large buffer size required: "
                      "%d bytes",
                      buf->size + copy_size);
        return false;
      }

      if (ngx_buf_in_memory(cl->buf)) {
        if (!sxg_write_bytes(cl->buf->pos, copy_size, buf)) {
          ngx_log_error(NGX_LOG_ERR, req->connection->log, 0,
                        "nginx-sxg-module: failed to allocate SXG buffer: "
                        "%d bytes",
                        copy_size);
          return false;
        }
        cl->buf->pos = cl->buf->last; /* Consuming buffer */
      } else if (cl->buf->in_file) {
        const size_t buffer_tail = buf->size;
        sxg_buffer_resize(buf->size + copy_size, buf);
        const ssize_t copied_size =
            ngx_read_file(cl->buf->file, buf->data + buffer_tail, copy_size,
                          cl->buf->file_pos);
        if (copied_size == NGX_ERROR || (size_t)copied_size != copy_size) {
          ngx_log_error(NGX_LOG_ERR, req->connection->log, 0,
                        "nginx-sxg-module: failed to read buffer from file");
          return false;
        }
        cl->buf->file_pos = cl->buf->file_last; /* Consuming buffer */
      }
      ngx_log_error(NGX_LOG_DEBUG, req->connection->log, 0,
                    "nginx-sxg-module: now sxg buffer is %d bytes", buf->size);
      *last_buf |= cl->buf->last_buf;
    }
  }
  return true;
}

static bool make_chain_from_buffer(ngx_http_request_t* req,
                                   const sxg_buffer_t* src, ngx_chain_t** dst) {
  ngx_buf_t* b = ngx_calloc_buf(req->pool);
  u_char* copied_buffer = ngx_palloc(req->pool, src->size);
  ngx_chain_t* out = ngx_alloc_chain_link(req->pool);
  if (b == NULL || copied_buffer == NULL || out == NULL) {
    ngx_pfree(req->pool, b);
    ngx_pfree(req->pool, copied_buffer);
    ngx_pfree(req->pool, out);
    return false;
  }
  ngx_memcpy(copied_buffer, src->data, src->size);
  b->start = b->pos = copied_buffer;
  b->end = b->last = b->pos + src->size;
  b->memory = b->last_buf = b->flush = 1;
  out->buf = b;
  out->next = NULL;
  *dst = out;
  return true;
}

static ngx_int_t ngx_http_sxg_body_filter(ngx_http_request_t* req,
                                          ngx_chain_t* in) {
  ngx_http_sxg_ctx_t* ctx =
      ngx_http_get_module_ctx(req, ngx_http_sxg_filter_module);

  if (ctx == NULL || req->done == true) {
    return ngx_http_next_body_filter(req, in);
  }

  if (pthread_mutex_lock(&ctx->lock) != 0) {
    return NGX_ERROR;
  }
  ngx_int_t result = ngx_http_sxg_body_filter_impl(req, ctx, in);

  if (pthread_mutex_unlock(&ctx->lock) != 0) {
    return NGX_ERROR;
  }

  if (result == NGX_OK || result == NGX_ERROR) {
    if (result == NGX_ERROR) {
      ngx_log_error(NGX_LOG_DEBUG, req->connection->log, 0,
                    "nginx-sxg-module: finalizing SXG request context");
    }
    release_ctx(req->pool, ctx);
  }

  return result;
}

static ngx_int_t ngx_http_sxg_body_filter_impl(ngx_http_request_t* req,
                                               ngx_http_sxg_ctx_t* ctx,
                                               ngx_chain_t* in) {
  ngx_http_sxg_loc_conf_t* slc =
      ngx_http_get_module_loc_conf(req, ngx_http_sxg_filter_module);

  if (req->header_sent) {
    return ngx_http_next_body_filter(req, in);
  }
  if (!ctx->main_resource_loaded) {
    bool lastbuf_included = false;
    if (copy_buffer_to_sxg_buffer(req, in, &ctx->response.payload,
                                  slc->sxg_max_payload, &lastbuf_included)) {
      if (lastbuf_included) {
        // Whole main resource body copied.
        ctx->main_resource_loaded = true;
      } else {
        return NGX_AGAIN;
      }
    } else {
      sxg_raw_response_release(&ctx->response);
      return NGX_ERROR;
    }
  }

  if (ctx->subresources > 0) {
    return NGX_AGAIN;
  }

  // Copy SXG headers to innerHTML header.
  if (!sxg_header_append_string("content-type",
                                (const char*)req->headers_out.content_type.data,
                                &ctx->response.header) ||
      !copy_response_header_to_sxg_header(req->pool, &req->headers_out.headers,
                                          &ctx->response.header)) {
    ngx_log_error(NGX_LOG_ERR, req->connection->log, 0,
                  "nginx-sxg-module: failed to copy headers to SXG");
    sxg_raw_response_release(&ctx->response);
    return NGX_ERROR;
  }

  // Cleanup outer headers and trailers.
  ngx_memzero(&req->headers_out, sizeof(ngx_http_headers_out_t));
  if (ngx_list_init(&req->headers_out.headers, req->pool, 2,
                    sizeof(ngx_table_elt_t)) != NGX_OK) {
    ngx_log_error(NGX_LOG_ERR, req->connection->log, 0,
                  "nginx-sxg-module: failed to initialize outer header list");
    return NGX_ERROR;
  }
  if (ngx_list_init(&req->headers_out.trailers, req->pool, 1,
                    sizeof(ngx_table_elt_t)) != NGX_OK) {
    ngx_log_error(NGX_LOG_ERR, req->connection->log, 0,
                  "nginx-sxg-module: failed to initialize trailers list");
    return NGX_ERROR;
  }
  req->headers_out.status = NGX_HTTP_OK;
  // Append nosniff to the new outer header entry.
  ngx_table_elt_t* x_content_type_options =
      ngx_list_push(&req->headers_out.headers);
  x_content_type_options->hash = 1;
  ngx_str_set(&x_content_type_options->key, "X-Content-Type-Options");
  ngx_str_set(&x_content_type_options->value, "nosniff");
  ngx_table_elt_t* vary = ngx_list_push(&req->headers_out.headers);
  vary->hash = 1;
  ngx_str_set(&vary->key, "Vary");
  ngx_str_set(&vary->value, "Accept");

  // Modify out of list outer header entries.
  ngx_str_set(&req->headers_out.content_type,
              "application/signed-exchange;v=b3");
  req->headers_out.content_type_len = req->headers_out.content_type.len;

  sxg_buffer_t sxg = sxg_empty_buffer();
  bool success = generate_sxg(req, ctx, &sxg);
  sxg_raw_response_release(&ctx->response);

  if (!success) {
    ngx_log_error(NGX_LOG_ERR, req->connection->log, 0,
                  "nginx-sxg-module: failed to generate sxg");
    sxg_buffer_release(&sxg);
    return NGX_ERROR;
  }
  req->done = true;
  req->headers_out.content_length_n = sxg.size;

  ngx_chain_t* out;
  if (!make_chain_from_buffer(req, &sxg, &out)) {
    return NGX_ERROR;
  }

  ngx_log_error(NGX_LOG_NOTICE, req->connection->log, 0,
                "nginx-sxg-module: Send sxg %l bytes, %d", sxg.size,
                req->header_sent);

  sxg_buffer_release(&sxg);

  if (!req->header_sent && ngx_http_next_header_filter(req) != NGX_OK) {
    return NGX_ERROR;
  }

  return ngx_http_next_body_filter(req, out);
}

static bool is_valid_config(ngx_conf_t* nc, const ngx_http_sxg_loc_conf_t* sc) {
  bool valid = true;
  if (sc->certificate.len == 0) {
    valid = false;
    if (sc->enable) {
      ngx_log_error(NGX_LOG_CRIT, nc->log, 0,
                    "nginx-sxg-module: sxg_certificate not specified");
    }
  }
  if (sc->certificate_key.len == 0) {
    valid = false;
    if (sc->enable) {
      ngx_log_error(NGX_LOG_CRIT, nc->log, 0,
                    "nginx-sxg-module: sxg_certificate_key not specified");
    }
  }
  if (sc->validity_url.len == 0) {
    valid = false;
    if (sc->enable) {
      ngx_log_error(NGX_LOG_CRIT, nc->log, 0,
                    "nginx-sxg-module: sxg_validity_url not specified");
    }
  }
  if (sc->cert_url.len == 0) {
    valid = false;
    if (sc->enable) {
      ngx_log_error(NGX_LOG_CRIT, nc->log, 0,
                    "nginx-sxg-module: sxg_cert_url not specified");
    }
  }
  return valid;
}

static ngx_int_t ngx_http_cert_chain_handler(ngx_http_request_t* req) {
  // Check the URL is a certificate request.
  ngx_http_sxg_loc_conf_t* slc =
      ngx_http_get_module_loc_conf(req, ngx_http_sxg_filter_module);
  if (slc->cert_path.len <= 0 || req->uri.len != slc->cert_path.len ||
      ngx_memcmp(req->uri.data, slc->cert_path.data, req->uri.len) != 0) {
    return NGX_OK;
  }
  if (pthread_mutex_lock(&slc->cert_chain_lock) != 0) {
    ngx_log_error(NGX_LOG_EMERG, req->connection->log, 0,
                  "nginx-sxg-module: Failed to acquire cert_chain_lock");
    return NGX_ERROR;
  }
  bool refreshed = refresh_if_needed(&slc->cert_chain);
  if (refreshed) {
    ngx_log_error(
        NGX_LOG_INFO, req->connection->log, 0,
        "nginx-sxg-module: OCSP Response in Certificate-Chain is refreshed");
  }
  req->headers_out.status = NGX_HTTP_OK;
  req->headers_out.content_length_n =
      slc->cert_chain.serialized_cert_chain.size;

  ngx_str_set(&req->headers_out.content_type, "application/cert-chain+cbor");
  req->headers_out.content_type_len = req->headers_out.content_type.len;
  req->headers_out.content_type_lowcase = NULL;

  ngx_chain_t* out;
  if (!make_chain_from_buffer(req, &slc->cert_chain.serialized_cert_chain,
                              &out)) {
    ngx_log_error(NGX_LOG_ERR, req->connection->log, 0,
                  "nginx-sxg-module: failed to generate Cert-Chain");
    return NGX_ERROR;
  }
  if (pthread_mutex_unlock(&slc->cert_chain_lock) != 0) {
    ngx_log_error(NGX_LOG_EMERG, req->connection->log, 0,
                  "nginx-sxg-module: Failed to release cert_chain_lock");
    return NGX_ERROR;
  }
  if (ngx_http_next_header_filter(req) != NGX_OK ||
      ngx_http_next_body_filter(req, out) != NGX_OK) {
    ngx_log_error(NGX_LOG_ERR, req->connection->log, 0,
                  "nginx-sxg-module: failed to return payload");
    return NGX_ERROR;
  }
  return NGX_DONE;
}

static ngx_int_t ngx_http_sxg_filter_init(ngx_conf_t* cf) {
  ngx_http_core_main_conf_t* cmcf =
      ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

  ngx_http_next_header_filter = ngx_http_top_header_filter;
  ngx_http_top_header_filter = ngx_http_sxg_header_filter;
  ngx_http_next_body_filter = ngx_http_top_body_filter;
  ngx_http_top_body_filter = ngx_http_sxg_body_filter;

  // Cert-Chain handler
  ngx_http_handler_pt* h =
      ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
  if (h == NULL) {
    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                  "nginx-sxg-module: initialization failed");
    return NGX_ERROR;
  }

  *h = ngx_http_cert_chain_handler;
  return NGX_OK;
}
