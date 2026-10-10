#!/usr/bin/env bash
# Self-contained L3 smuggling differential: start Go backend + pingora proxy,
# send attack vectors through the proxy, check whether the backend (Go
# net/http) ever sees a hidden /SMUGGLED request. Tears everything down.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PINGORA="$HERE/../pingora"
PIPE="${1:-0}"   # arg1: L3_PIPELINING (0/1)

pkill -f "$HERE/backend" 2>/dev/null
pkill -f 'examples/l3proxy' 2>/dev/null
sleep 1

: > "$HERE/backend.log"
"$HERE/backend" 2>> "$HERE/backend.log" &
BPID=$!
RUST_LOG=error L3_PIPELINING="$PIPE" "$PINGORA/target/release/examples/l3proxy" \
    2>> "$HERE/proxy.log" &
PPID_=$!
sleep 2

python3 -I "$HERE/driver.py"
RC=$?

kill "$BPID" "$PPID_" 2>/dev/null
wait 2>/dev/null

echo "===== BACKEND LOG ====="
grep -nE 'BACKEND_REQ|SMUGGLED' "$HERE/backend.log" | tail -60
echo "===== SMUGGLED HITS ====="
if grep -q 'path="/SMUGGLED"' "$HERE/backend.log"; then
    echo "!!! DESYNC: backend saw a smuggled request"
    grep -n 'path="/SMUGGLED"' "$HERE/backend.log"
else
    echo "none (no desync observed by the backend)"
fi
exit $RC
