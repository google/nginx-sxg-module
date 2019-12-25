ARG base_image
FROM ${base_image}

LABEL maintainer "Hiroki Kumazaki <kumagi@google.com>"

RUN /packaging/build_deb /libsxg; \
    dpkg -i /packaging/output/libsxg0.2_0.2-1_amd64.deb; \
    dpkg -i /packaging/output/libsxg-dev_0.2-1_amd64.deb || true

RUN cat /etc/apt/sources.list \
    | grep "^deb " \
    | sed -e "s/^deb /deb-src /" \
    >> /etc/apt/sources.list
RUN apt-get update && \
    apt-get install -y --no-install-recommends -q \
                    dpkg-dev && \
    apt-get build-dep -y --no-install-recommends -q \
                      nginx-full


ADD . /nginx-sxg-module
WORKDIR /nginx-sxg-module

ENTRYPOINT ["packaging/build_deb", "docker_output"]

