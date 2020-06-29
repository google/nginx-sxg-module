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
curl -H"Host:nginx-sxg.test" -H"Accept:application/signed-exchange;v=b3" https://127.0.0.1/a -k --output - > /data/result/a.sxg
curl -H"Host:nginx-sxg.test" -H"Accept:application/signed-exchange;v=b3" https://127.0.0.1/b -k --output - > /data/result/b.sxg
curl -H"Host:nginx-sxg.test" -H"Accept:application/signed-exchange;v=b3" https://127.0.0.1/c -k --output - > /data/result/c.sxg
cp /var/log/nginx/error.log /data/result/
chmod -R 755 /data/result

cat result/index.sxg
cat result/error.log

