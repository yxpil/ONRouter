#!/usr/bin/env bash
# Upstream keep-alive empirical E2E.
#  Proves the pool actually reuses backend connections (default long idle timeout)
#  AND that `keepalive_timeout` is wired to the pool: a tiny timeout makes the idle
#  connection get reaped between spaced-out requests, so the backend sees a new TCP
#  connection every time. The fake backend reports a cumulative connection counter.
#
#   cargo build -p onrouter-server --bin onrouter && bash tools/keepalive_e2e.sh
set -u
cd "$(dirname "$0")/.." || exit 2

if [ -x ./target/debug/onrouter.exe ]; then BIN=./target/debug/onrouter.exe; else BIN=./target/debug/onrouter; fi
[ -x "$BIN" ] || { echo "!! $BIN missing; run cargo build -p onrouter-server --bin onrouter"; exit 2; }
PY=$(command -v python || command -v python3)
[ -n "$PY" ] || { echo "!! python not found"; exit 2; }

mkdir -p logs
pass=0; fail=0
ok()  { echo "  PASS: $1"; pass=$((pass+1)); }
bad() { echo "  FAIL: $1"; fail=$((fail+1)); }

PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done; }
trap cleanup EXIT

start_bg() { "$@" >/dev/null 2>&1 & p=$!; PIDS+=("$p"); echo "$p"; }
wait_http() { # url  max_iters
  local url=$1 n=${2:-40}
  for _ in $(seq 1 "$n"); do curl -s -o /dev/null --max-time 1 "$url" && return 0; sleep 0.2; done
  return 1
}
total_of() { grep -oE '"total_conns":[[:space:]]*[0-9]+' | grep -oE '[0-9]+$'; }
conn_of() { grep -oE '"conn_id":[[:space:]]*[0-9]+' | grep -oE '[0-9]+$'; }

# Assert on DISTINCT conn_ids across the four timed requests, not the absolute
# counter: the readiness probes (wait_http) already open backend connections, so
# total_conns is inflated before the measured window. Reuse shows up as all four
# requests landing on the SAME backend connection; a reaped pool shows four
# DIFFERENT connections.
run_phase() { # name  backend_port  conf  onrouter_port  gap  expect_distinct
  local name=$1 bp=$2 conf=$3 lp=$4 gap=$5 expect=$6
  echo "== [$name] backend :$bp  onrouter :$lp  conf=$conf  gap=${gap}s =="
  start_bg "$PY" tools/keepalive_backend.py "$bp" >/dev/null
  wait_http "http://127.0.0.1:${bp}/" 30 || { bad "$name: backend never came up"; return; }
  start_bg "$BIN" -c "$conf" >/dev/null
  wait_http "http://127.0.0.1:${lp}/" 40 || { bad "$name: onrouter never became ready"; return; }

  local ids=""
  for i in 1 2 3 4; do
    local body; body=$(curl -s --max-time 2 "http://127.0.0.1:${lp}/")
    local cid; cid=$(printf '%s' "$body" | conn_of)
    [ -n "$cid" ] || { bad "$name: req#$i empty body (backend/proxy not responding?)"; return; }
    ids="$ids $cid"
    echo "  req#$i -> conn_id=$cid"
    sleep "$gap"
  done
  echo "  conn_id sequence:$ids"
  local distinct; distinct=$(printf '%s\n' $ids | sort -u | grep -c .)
  if [ "$distinct" = "$expect" ]; then
    ok "$name: $distinct distinct backend connection(s), as expected"
  else
    bad "$name: expected $expect distinct connection(s), got $distinct ($ids)"
  fi
}

# Phase A: default long idle timeout => the 4 requests reuse ONE backend connection.
run_phase REUSE 18110 conf/ka_reuse.conf 18101 0.2 1
# Phase B: keepalive_timeout 100ms, requests 0.3s apart => connection reaped each time => 4 connections.
run_phase SHORT 18111 conf/ka_short.conf 18102 0.3 4

cleanup
echo; echo "================ keep-alive E2E: PASS=${pass} FAIL=${fail} ================"
[ "$fail" = 0 ] && echo "ALL GREEN" || { echo "SOME FAILED"; exit 1; }
