#!/usr/bin/env bash
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PINGORA="$HERE/../pingora"
PIPE="${1:-0}"
pkill -9 -f 'target/release/examples/l3proxy' 2>/dev/null
pkill -9 -f "$HERE/backend" 2>/dev/null
sleep 1
: > "$HERE/backend.log"; : > "$HERE/proxy.log"
"$HERE/backend" 2>> "$HERE/backend.log" &
RUST_LOG=error L3_PIPELINING="$PIPE" "$PINGORA/target/release/examples/l3proxy" 2>> "$HERE/proxy.log" &
sleep 2
timeout 60 python3 -I "$HERE/driver.py"
echo "driver rc=$?"
sleep 1
pkill -9 -f 'target/release/examples/l3proxy' 2>/dev/null
pkill -9 -f "$HERE/backend" 2>/dev/null
echo "===== BACKEND REQUESTS (pipelining=$PIPE) ====="
grep -nE 'BACKEND_REQ' "$HERE/backend.log" | tail -60
echo "===== /SMUGGLED AS A REQUEST? ====="
if grep -q 'path="/SMUGGLED"' "$HERE/backend.log"; then
    echo "!!! DESYNC: backend parsed a standalone /SMUGGLED request"
    grep -n 'path="/SMUGGLED"' "$HERE/backend.log"
else
    echo "none — no /SMUGGLED request reached the backend"
fi
