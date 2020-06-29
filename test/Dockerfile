ARG base_image
FROM ${base_image}

WORKDIR /data
RUN apt-get update && apt-get install -y nginx wget unzip curl && \
    apt-get install -y libssl-dev && \
    wget https://github.com/google/libsxg/releases/download/v0.2/libsxg0_0.2-1_amd64.deb && \
    wget https://github.com/google/libsxg/releases/download/v0.2/libsxg-dev_0.2-1_amd64.deb && \
    dpkg -i libsxg0_0.2-1_amd64.deb && \
    dpkg -i libsxg-dev_0.2-1_amd64.deb

COPY libnginx-mod-http-sxg-filter*.deb .
RUN dpkg -i libnginx-mod-http-sxg-filter*.deb

COPY ssl.crt .
COPY ssl.key .
COPY sxg.crt .
COPY sxg.key .
COPY nginx-sxg.conf /etc/nginx/sites-enabled/
COPY index.html /var/www/nginx-sxg.test/
COPY index.html /var/www/nginx-sxg.test/foo/
COPY index.html /var/www/nginx-sxg.test/bar/
RUN mkdir result
RUN chmod 755 -R /var/www/nginx-sxg.test/

COPY selfcheck.sh .

EXPOSE 443

ENTRYPOINT ["./selfcheck.sh"]
