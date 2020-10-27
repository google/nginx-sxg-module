# NGINX SXG extension

[![Build Status](https://travis-ci.org/google/nginx-sxg-module.svg?branch=master)](https://travis-ci.org/google/nginx-sxg-module)

Signed HTTP Exchange (SXG) support for nginx. Nginx will convert responses from
the upstream application into SXG when client requests include the `Accept:
application/signed-exchane;v=b3` HTTP header with highest qvalue.

## Installation

There are two options for installation: Debian package or build from source. See
[this article](https://web.dev/how-to-set-up-signed-http-exchanges/) for more
details.

## Configuration

Nginx-SXG module requires configuration on nginx.

### Directives

#### sxg

Activation flag of SXG module.

- `on`: Enable this plugin.
- `off`: Disable this plugin.

Default value is `off`.

#### sxg\_certificate

Full path for the certificate file. The certificate requires all of the
conditions below to match.

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

An absolute path in which nginx will generate and serve the CBOR-encoded certificate file.
But make sure that the OCSP responder for the certificate is accessible from your nginx server to get OCSP responses.
This directive is optional.

#### sxg\_expiry\_seconds

The life-span of generated SXG file in seconds.
It must not be bigger than 604800 (1 week).
This directive is optional.
The default value is `86400` (1 day).

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
        sxg_expires_seconds 604800;

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
