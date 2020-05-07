ARG base_image
FROM ${base_image}

LABEL maintainer "Hiroki Kumazaki <kumagi@google.com>"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends -q \
                    build-essential \
                    ca-certificates \
                    cmake \
                    debhelper \
                    devscripts \
                    dpkg-dev \
                    fakeroot \
                    git \
                    libssl-dev \
                    lsb-release \
                    moreutils \
                    wget

RUN grep -q "# deb-src" /etc/apt/sources.list && sed -i -e 's/^# deb-src /deb-src /' /etc/apt/sources.list || \
    sed -e "s/^deb /deb-src /" < /etc/apt/sources.list | grep "^deb-src" | sponge -a /etc/apt/sources.list

RUN cat /etc/apt/sources.list
RUN apt-get update && apt-get build-dep -y -q nginx-full

RUN wget https://github.com/google/libsxg/releases/download/v0.2/libsxg0_0.2-1_amd64.deb && \
    wget https://github.com/google/libsxg/releases/download/v0.2/libsxg-dev_0.2-1_amd64.deb && \
    dpkg -i libsxg0_0.2-1_amd64.deb && \
    dpkg -i libsxg-dev_0.2-1_amd64.deb

ADD . /nginx-sxg-module
WORKDIR /nginx-sxg-module

CMD ["packaging/build_deb", "./output"]
