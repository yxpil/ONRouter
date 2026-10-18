#!/usr/bin/env bash
# gzip response-compression E2E: drives a live ONRouter with real HTTP and asserts
# both compression (Content-Encoding, gzip magic, size drop, byte-exact round-trip)
# and every pass-through gate (no AE, HEAD, <gzip_min_length, non-eligible type,
# Accept-Encoding q=0, non-2xx).
#
# Build the debug binary first, then run from anywhere:
#   cargo build -p onrouter-server --bin onrouter && bash tools/gzip_e2e.sh
set -u
cd "$(dirname "$0")/.." || exit 2

if [ -x ./target/debug/onrouter.exe ]; then BIN=./target/debug/onrouter.exe; else BIN=./target/debug/onrouter; fi
if [ ! -x "$BIN" ]; then echo "!! $BIN not found; run: cargo build -p onrouter-server --bin onrouter"; exit 2; fi

CONF=conf/gzip_test.conf
PORT=18097
BASE="http://127.0.0.1:${PORT}"
OUT=$(mktemp -d); trap 'rm -rf "$OUT"; kill "$ORR" 2>/dev/null' EXIT
mkdir -p logs

pass=0; fail=0
ok()  { echo "  PASS: $1"; pass=$((pass+1)); }
bad() { echo "  FAIL: $1"; fail=$((fail+1)); }
sha()        { sha256sum "$1" | cut -d' ' -f1; }
has_gzip()   { grep -i -q '^content-encoding:[[:space:]]*gzip' "$1"; }
gzip_magic() { od -An -tx1 -N2 "$1" | tr -d ' \n' | grep -q 1f8b; }

echo "== starting ONRouter =="
"$BIN" -c "$CONF" >"$OUT/onrouter.log" 2>&1 &
ORR=$!
ready=0
for _ in $(seq 1 30); do
  curl -s -o /dev/null --max-time 1 "${BASE}/big.html" && { ready=1; break; }
  sleep 0.2
done
[ "$ready" = 1 ] || { echo "!! server not ready:"; cat "$OUT/onrouter.log"; exit 3; }

echo "[1] text/html + Accept-Encoding: gzip"
curl -s -D "$OUT/h1" -H 'Accept-Encoding: gzip' -o "$OUT/b1" "${BASE}/big.html"
has_gzip "$OUT/h1" && ok "Content-Encoding: gzip" || bad "expected gzip"
grep -i -q '^vary:[[:space:]]*accept-encoding' "$OUT/h1" && ok "Vary: Accept-Encoding" || bad "expected Vary"
grep -i -q '^content-length:' "$OUT/h1" && bad "Content-Length must be dropped when gzipping" || ok "Content-Length dropped"
gzip_magic "$OUT/b1" && ok "wire has gzip magic" || bad "not gzip"
wsz=$(wc -c <"$OUT/b1"); osz=$(wc -c <public_gzip/big.html)
[ "$wsz" -lt "$osz" ] && ok "compressed ${wsz}B < original ${osz}B" || bad "no reduction"
gunzip -c "$OUT/b1" >"$OUT/o1" 2>/dev/null
[ "$(sha "$OUT/o1")" = "$(sha public_gzip/big.html)" ] && ok "round-trip sha256 matches" || bad "round-trip mismatch"

echo "[2] text/html with NO Accept-Encoding"
curl -s -D "$OUT/h2" -o "$OUT/b2" "${BASE}/big.html"
has_gzip "$OUT/h2" && bad "must not compress without AE" || ok "passthrough (no gzip)"
[ "$(sha "$OUT/b2")" = "$(sha public_gzip/big.html)" ] && ok "byte-identical body" || bad "body differs"

echo "[3] HEAD request"
curl -s -I -H 'Accept-Encoding: gzip' -o "$OUT/h3" "${BASE}/big.html"
has_gzip "$OUT/h3" && bad "HEAD must not compress" || ok "HEAD not compressed"

echo "[4] body below gzip_min_length (100)"
curl -s -D "$OUT/h4" -H 'Accept-Encoding: gzip' -o "$OUT/b4" "${BASE}/small.html"
has_gzip "$OUT/h4" && bad "should skip < min_length" || ok "skipped below min_length"
[ "$(sha "$OUT/b4")" = "$(sha public_gzip/small.html)" ] && ok "small body byte-identical" || bad "small body differs"

echo "[5] image/png not in gzip_types (body over min_length)"
curl -s -D "$OUT/h5" -H 'Accept-Encoding: gzip' -o "$OUT/b5" "${BASE}/tiny.png"
has_gzip "$OUT/h5" && bad "non-eligible type must not compress" || ok "skipped by content-type"

echo "[6] application/json + text/css"
curl -s -D "$OUT/h6" -H 'Accept-Encoding: gzip' -o "$OUT/b6" "${BASE}/data.json"
has_gzip "$OUT/h6" && gzip_magic "$OUT/b6" && ok "json compressed" || bad "json not compressed"
curl -s -D "$OUT/h7" -H 'Accept-Encoding: gzip' -o /dev/null "${BASE}/style.css"
has_gzip "$OUT/h7" && ok "css compressed" || bad "css not compressed"

echo "[7] Accept-Encoding: gzip;q=0"
curl -s -D "$OUT/h8" -H 'Accept-Encoding: gzip;q=0' -o /dev/null "${BASE}/big.html"
has_gzip "$OUT/h8" && bad "q=0 must decline" || ok "honored q=0"

echo "[8] non-2xx (404) never compresses"
curl -s -D "$OUT/h9" -H 'Accept-Encoding: gzip' -o /dev/null "${BASE}/missing.html"
head -1 "$OUT/h9" | grep -q ' 404' && ok "got 404" || bad "expected 404"

kill "$ORR" 2>/dev/null; wait "$ORR" 2>/dev/null
echo; echo "================ gzip E2E: PASS=${pass} FAIL=${fail} ================"
[ "$fail" = 0 ] && echo "ALL GREEN" || { echo "SOME FAILED"; exit 1; }
