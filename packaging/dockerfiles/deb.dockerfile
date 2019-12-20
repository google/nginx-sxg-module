ARG base_image
FROM ${base_image}

LABEL maintainer "Hiroki Kumazaki <kumagi@google.com>"

RUN mkdir /libsxg/build -p && \
    cd /libsxg/build && \
    cmake .. -DSKIP_TEST=true -DCMAKE_BUILD_TYPE=Release && \
    make && \
    make install
    
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

