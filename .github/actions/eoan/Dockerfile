FROM ubuntu:eoan

LABEL maintainer "Hiroki Kumazaki <kumagi@google.com>"

RUN grep -q "# deb-src" /etc/apt/sources.list && sed -Ei 's/^# deb-src /deb-src /' /etc/apt/sources.list || \
    cat /etc/apt/sources.list | grep "^deb " | sed -e "s/^deb /deb-src /" | tee -a /etc/apt/sources.list && \
    apt-get update && \
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
                    pbuilder && \
    apt-get build-dep -y --no-install-recommends -q \
            nginx-full && \
    rm -rf /var/lib/apt/lists/*

RUN git clone -b debian http://github.com/google/libsxg.git /libsxg && \
    cd /libsxg && \
    sed -i -e "s/^debuild/debuild -uc -us/" build_deb && \
    sed -i -e "s/^lintian.*$//g" build_deb && \
    ./build_deb http://github.com/google/libsxg && \
    dpkg -i output/libsxg0.2_0.2-1_amd64.deb && \
    dpkg -i output/libsxg-dev_0.2-1_amd64.deb

ADD . /nginx-sxg-module
WORKDIR /nginx-sxg-module

CMD ["packaging/build_deb", "./"]