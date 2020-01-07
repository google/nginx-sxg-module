#!/bin/sh
VERSION="0.2"
LIBSXG_ZIP=libsxg.zip
travis_retry wget "https://github.com/google/libsxg/archive/v${VERSION}.zip" -O "${LIBSXG_ZIP}"
echo "c270c04be92441747a9d1c5820893a18  ${LIBSXG_ZIP}" > libsxg_md5.txt
md5sum -c libsxg_md5.txt
unzip ${LIBSXG_ZIP}
mkdir -p libsxg-${VERSION}/build
pushd libsxg-${VERSION}/build
  cmake .. -DRUN_TEST=FALSE
  make
  sudo make install
popd
