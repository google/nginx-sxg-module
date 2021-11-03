# NGINX SXG module

[![Build Status](https://travis-ci.org/google/nginx-sxg-module.svg?branch=master)](https://travis-ci.org/google/nginx-sxg-module)

Signed HTTP Exchange (SXG) support for nginx. Nginx will convert responses from
the upstream application into SXG when client requests include the `Accept:
application/signed-exchange;v=b3` HTTP header with highest qvalue.

## Installation

There are two options for installation: Debian package or build from source. See
[this article](https://web.dev/how-to-set-up-signed-http-exchanges/) for more
details.

If building from source and you have libsxg installed in a non-system
directory, edit `config` to add `ngx_module_incs=path/to/include` and add
`-Lpath/to/lib` to the existing `ngx_module_libs`, and launch nginx with
`LD_LIBRARY_PATH=path/to/lib`.

## Configuration

Nginx-SXG module requires configuration on nginx.

### Directives

#### sxg

Activation flag of SXG module. This can be set or overriden inside `server`
and `location` directives.

- `on`: Enable this plugin.
- `off`: Disable this plugin.

Default value is `off`.

#### sxg\_certificate

Full path for the certificate file. The certificate requires all of the
conditions below to match. This and all below directives can only be set
inside `server` directives.

- Has `CanSignHttpExchanges` extension.
- Uses ECDSA256 or ECDSA384.

This directive is always required.

#### sxg\_certificate\_key

Full path for the private key for the certificate.

This directive is always required.

#### sxg\_cert\_url

URL for CBOR encoded certificate file. The protocol must be `https`.

This directive is always required.

#### sxg\_validity\_url

URL for the validity information file. It must be `https` and must be the same
origin with the website.

This directive is always required.

#### sxg\_max\_payload

Maximum HTTP body size this module can generate SXG from. Default value is
`67108864` (64 MiB).


#### sxg\_cert\_path

This directive is optional. If specified, this should be an absolute path
corresponding to a file that will be served at the URL specified by
`sxg_cert_url`. This plugin will then automatically generate and refresh the
CBOR-encoded certificate file, given the PEM located at `sxg_certificate`. It
requires that the OCSP responder for the certificate is accessible from your
nginx server to get OCSP responses.

Alternatively, use
[`gen-certurl`](https://github.com/WICG/webpackage/blob/main/go/signedexchange/README.md)
to generate a new `cert-chain+cbor` daily, and serve it statically at the URL
specified by `sxg_cert_url`.

#### sxg\_expiry\_seconds

The life-span of generated SXG file in seconds.
It must not be bigger than 604800 (1 week).
This directive is optional.
The default value is `86400` (1 day).

#### sxg\_fallback\_host

The hostname of fallback url of generated SXG file.
This directive is optional.
The default value is Host field parameter of HTTP request header.

### Config Example

```
load_module "modules/ngx_http_sxg_filter_module.so";

http {
    upstream app {
        server 127.0.0.1:3000;
    }
    include       mime.types;
    default_type  application/octet-stream;
    subrequest_output_buffer_size   4096k;

    server {
        listen    80;
        server_name  example.com;

        sxg on;
        sxg_certificate     /path/to/certificate-ecdsa.pem;
        sxg_certificate_key /path/to/private-key-ecdsa.key;
        sxg_cert_url        https://cdn.test.com/example.com.cert.cbor;
        sxg_validity_url    https://example.com/validity/resource.msg;
        sxg_expiry_seconds 604800;
        sxg_fallback_host  example.com;

        location / {
            proxy_pass http://app;
        }
    }
}
```

### Subresource support

nginx-sxg-module automatically includes signatures of subresources in its responses, allowing end users to prefetch it from distributor.
When finding `link: rel="preload"` entry in HTTP response header from upstream, this plugin will collect the specified resource to the upstream and append `rel="allowed-alt-sxg";header-integrity="sha256-...."` to the original HTTP response automatically.
This functionality is essential to subresource preloading for faster cross-site navigation.

  - Preload URLs must be [relative references](https://tools.ietf.org/html/rfc3986#section-4.2)
    of the `path-absolute` form, such as: `Link: </app.js>;rel=preload;as=script`.
  - The [`server_name`](https://nginx.org/en/docs/http/ngx_http_core_module.html#server_name)
    must match the externally-addressable host:port of the subresources.
  - Their responses must be no larger than the configured
    [`subrequest_output_buffer_size`](https://nginx.org/en/docs/http/ngx_http_core_module.html#subrequest_output_buffer_size).
  - Their responses must come from an upstream server, such as via
    [`proxy_pass`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_pass).
    The upstream may optionally be named via
    [`upstream`](https://nginx.org/en/docs/http/ngx_http_upstream_module.html#upstream).
  - If [using variables in
    `proxy_pass`](http://nginx.org/en/docs/http/ngx_http_proxy_module.html#non_idempotent:~:text=When%20variables%20are%20used%20in%20proxy_pass),
    use
    [`$uri`](http://nginx.org/en/docs/http/ngx_http_core_module.html#var_uri:~:text=1.2.7%29-,%24uri,current%20URI%20in%20request)
    instead of
    [`$request_uri`](http://nginx.org/en/docs/http/ngx_http_core_module.html#var_request_uri:~:text=%24request_uri,full%20original%20request%20URI).

To ensure subresource prefetching works, verify that the `header-integrity` in:

```bash
curl -H 'Accept: application/signed-exchange;v=b3' https://url/of/page.html | dump-signedexchange -payload=false | grep Link:
```

equals the value of:

```bash
curl -H 'Accept: application/signed-exchange;v=b3' https://url/of/subresource.jpg | dump-signedexchange -headerIntegrity
```
