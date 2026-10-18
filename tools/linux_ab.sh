#!/usr/bin/env bash
# Linux 同机 A/B：ONRouter vs OpenResty（同端点、同 Lua 源码、同 Python 后端）。
#
#   tools/linux_ab.sh                 # 默认 sweep 1,4,8,16 / 每格 20000 请求
#   SWEEP=1,4 REQUESTS=12000 tools/linux_ab.sh
#   OPENRESTY_NGINX=/opt/openresty/nginx/sbin/nginx tools/linux_ab.sh
#
# 依赖：Linux、cargo、python3、OpenResty（含 lua-nginx-module）。
# 产物：bench_linux_ab.json + .bench_openresty/logs/；脚本不写系统目录。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="$ROOT/.bench_openresty"
SWEEP="${SWEEP:-1,4,8,16}"
REQUESTS="${REQUESTS:-20000}"
TARGETS="${TARGETS:-orr,or}"

find_nginx() {
    if [[ -n "${OPENRESTY_NGINX:-}" ]]; then
        echo "$OPENRESTY_NGINX"; return
    fi
    local c
    for c in \
        /usr/local/openresty/nginx/sbin/nginx \
        /usr/local/openresty/bin/openresty \
        "$(command -v openresty || true)" \
        "$(command -v nginx || true)"; do
        if [[ -n "$c" && -x "$c" ]]; then echo "$c"; return; fi
    done
    echo "!! 找不到 OpenResty/nginx；安装 OpenResty 或设置 OPENRESTY_NGINX" >&2
    exit 1
}

NGINX="$(find_nginx)"
mkdir -p "$PREFIX/conf" "$PREFIX/logs" "$PREFIX/temp"
sed "s|__REPO__|$ROOT|g" "$ROOT/tools/openresty_bench.conf.tmpl" > "$PREFIX/conf/bench.conf"

cleanup() {
    "$NGINX" -p "$PREFIX" -s quit >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "== 构建 ONRouter（release） =="
cargo build --release -p onrouter-server --bin onrouter --manifest-path "$ROOT/Cargo.toml"

export ONROUTER_EXE="$ROOT/target/release/onrouter"
export OPENRESTY_DIR="$PREFIX"
export OPENRESTY_NGINX="$NGINX"

echo "== A/B：sweep=$SWEEP requests=$REQUESTS targets=$TARGETS =="
echo "   nginx=$NGINX"
echo "   prefix=$PREFIX"
python3 "$ROOT/bench_ab.py" \
    --targets "$TARGETS" --sweep "$SWEEP" --requests "$REQUESTS" \
    --json "$ROOT/bench_linux_ab.json"

echo
echo "原始数据：$ROOT/bench_linux_ab.json"
echo "提示：结果对 CPU 频率/后台负载敏感，跑前清空系统负载，至少重复 3 次取中位数。"
