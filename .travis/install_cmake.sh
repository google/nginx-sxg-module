#!/bin/sh

DEPS_DIR="${TRAVIS_BUILD_DIR}/deps"
mkdir ${DEPS_DIR} && pushd ${DEPS_DIR}
  CMAKE="cmake-3.15.2-Linux-x86_64"
  CMAKE_TAR="${CMAKE}.tar.gz"
  travis_retry wget https://github.com/Kitware/CMake/releases/download/v3.15.2/${CMAKE_TAR}
  echo "bf433a0e0674cfb358b127e7120dccaa ${CMAKE_TAR}" > cmake_md5.txt
  md5sum -c cmake_md5.txt
  tar -xf ${CMAKE_TAR}
  mv ${CMAKE} cmake-install
  export PATH=${DEPS_DIR}/cmake-install:${DEPS_DIR}/cmake-install/bin:$PATH
popd
