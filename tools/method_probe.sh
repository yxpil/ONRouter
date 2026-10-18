#!/bin/bash
# 在单个 Bash 调用内启动 ONRouter、探测、关闭
cd /c/Users/User/Desktop/LearnON || exit 1
./target/debug/onrouter.exe -p C:/tmp/lsmoke2/ -c nginx.conf -g "pid C:/tmp/lsmoke2/nginx.pid;" >/dev/null 2>&1 &
LP=$!
ok=0
for k in $(seq 1 20); do
  if curl -s -o /dev/null http://127.0.0.1:9802/; then ok=1; break; fi
  sleep 1
done
echo "startup_ok=$ok"
for m in GET DELETE PROPFIND MKCOL PATCH OPTIONS FOOBAR; do
  code=$(curl -s -X "$m" -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:9802/)
  echo "$m: $code"
done
taskkill //F //PID "$LP" >/dev/null 2>&1
