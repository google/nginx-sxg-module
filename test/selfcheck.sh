#!/bin/bash -ex

if ! service nginx restart; then
  cat /var/log/nginx/error.log
  exit 1
fi

rm -rf out
mkdir out
curl -sko- -H"Host:nginx-sxg.test" -H"Accept:application/signed-exchange;v=b3" https://127.0.0.1/bar/ -k --output - > /data/result/index.sxg
curl -sko- -H"Host:nginx-sxg.test" -H"Accept:application/signed-exchange;v=b3" https://127.0.0.1/foo/ > /data/result/index.html
curl -siko- -H"Host:nginx-sxg.test" -H"Accept:application/signed-exchange;v=b3" https://127.0.0.1/bar/ | tr -d '\r' | egrep -a -m1 -B999 '^$' > /data/result/index.header
curl -sko- -H"Host:nginx-no-sxg.test" -H"Accept:application/signed-exchange;v=b3" http://127.0.0.1:8080/ > /data/result/http.html

cp /var/log/nginx/error.log /data/result/
chmod -R 755 /data/result

cat result/index.sxg
cat result/error.log

echo "####### selfcheck finished #######"
