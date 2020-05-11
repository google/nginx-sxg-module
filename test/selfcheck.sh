#!/bin/bash -ex

cat /etc/nginx/sites-enabled/default
cat /etc/nginx/sites-enabled/nginx-sxg.conf
rm /etc/nginx/sites-enabled/default
service nginx restart

rm -rf out
mkdir out
curl -H"Host:nginx-sxg.test" -H"Accept:application/signed-exchange;v=b3" https://127.0.0.1/ -k --output - > /data/result/index.sxg
cp /var/log/nginx/error.log /data/result/
chmod -R 755 /data/result

cat result/index.sxg
cat result/error.log
#cat /etc/nginx/nginx.conf
