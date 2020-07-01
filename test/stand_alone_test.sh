#!/bin/bash -ex

if [ -z "$1" ]; then
   echo "Please set base image name."
   echo "e.g. $ stand_alone_test.sh debian:buster"
   exit
fi

BASE_IMAGE=${1}

rm libnginx-* -rf
pushd ..
docker build --build-arg base_image=${BASE_IMAGE} -t tmp_image -f packaging/deb.dockerfile .
docker run --rm --mount "type=bind,source=$(pwd)/test,target=/nginx-sxg-module/output" tmp_image
popd

rm -rf out && mkdir out
./generate.sh

docker build --build-arg base_image=${BASE_IMAGE} -t nginx .
docker run --mount type=bind,src=$(pwd)/out,dst=/data/result nginx

cat out/error.log | grep content-type -i -q
echo "${BASE_IMAGE}: Success."

rm rm libnginx-* *.key *.crt -rf
