#!/bin/bash -ex

if ! service nginx restart; then
  cat /var/log/nginx/error.log
  return 1
fi

rm -rf out
mkdir out
curl -i -H"Host:nginx-sxg.test" -H"Accept:application/signed-exchange;v=b3" https://127.0.0.1/bar/ -k --output - > /data/result/index.sxg
curl -i -H"Host:nginx-sxg.test" -H"Accept:application/signed-exchange;v=b3" https://127.0.0.1/foo/ -k --output - > /data/result/index.html
curl -i -H"Host:nginx-sxg.test" -H"Accept:application/signed-exchange;v=b3" https://127.0.0.1/bar/ -k --output - | egrep -m1 -B999 '^$'> /data/result/index.header
curl -H"Host:nginx-no-sxg.test" -H"Accept:application/signed-exchange;v=b3" http://127.0.0.1:8080/ -k --output - > /data/result/http.html


cp /var/log/nginx/error.log /data/result/
chmod -R 755 /data/result

cat result/index.sxg
cat result/error.log

