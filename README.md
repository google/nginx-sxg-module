# NGINX SXG extension

Signed HTTP Exchange(SXG) support for nginx. Nginx will convert response from
upstream application into SXG, only for clients request on `Accept:
application/signed-exchane;v=b3` with highest qvalue.

## Configuration

Nginx-SXG module requires configuration on nginx.

### Directives

#### sxg

Activation flag of SXG module.

-   `on`: Enable this plugin.
-   `off`: Disable this plugin.

Default value is `off`.

#### sxg\_certificate

Full path for the certificate file. The certificate requires all of the
conditions below to match.

-   Has `CanSignHttpExchanges` extension.
-   Uses ECDSA256 or ECDSA384.

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
`67108864`(64MiB).

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

        location / {
            proxy_pass http://app;
        }
    }
}
```
