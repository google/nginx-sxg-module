#!/bin/sh
OPENSSL="OpenSSL_1_1_1c"
OPENSSL_ZIP="${OPENSSL}.zip"
travis_retry wget --no-check-certificate https://github.com/openssl/openssl/archive/${OPENSSL_ZIP}
echo "e519cd282e7a94ea1d72f223ba792ad0  ${OPENSSL_ZIP}" > openssl_md5.txt
md5sum -c openssl_md5.txt
unzip ${OPENSSL_ZIP}
pushd openssl-${OPENSSL}
./config
make -j`nproc`
sudo make install
popd
