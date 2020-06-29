#!/bin/bash -ex

cat /etc/nginx/sites-enabled/default
cat /etc/nginx/sites-enabled/nginx-sxg.conf
rm /etc/nginx/sites-enabled/default

if ! service nginx restart; then
  cat /var/log/nginx/error.log
  return 1
fi

rm -rf out
mkdir out
curl -H"Host:nginx-sxg.test" -H"Accept:application/signed-exchange;v=b3" https://127.0.0.1/bar/ -k --output - > /data/result/index.sxg
curl -H"Host:nginx-sxg.test" -H"Accept:application/signed-exchange;v=b3" https://127.0.0.1/foo/ -k --output - > /data/result/index.html
curl -H"Host:nginx-no-sxg.test" -H"Accept:application/signed-exchange;v=b3" http://127.0.0.1:8080/ -k --output - > /data/result/http.html
cp /var/log/nginx/error.log /data/result/
chmod -R 755 /data/result

cat result/index.sxg
cat result/error.log
#cat /etc/nginx/nginx.conf
