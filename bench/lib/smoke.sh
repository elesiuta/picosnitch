#!/usr/bin/env bash
# One-shot foundation smoke test: proves netlab + server + generators + the
# dual-layer ground truth all agree. Runs entirely as root in one process so
# the peer server is a normal child that is reaped on exit (no orphans).
set -uo pipefail
cd "$(dirname "$0")/.."
BIN=./bin
srv_pid=""
cleanup() { [ -n "$srv_pid" ] && kill "$srv_pid" 2>/dev/null; bash lib/netlab.sh down 2>/dev/null; }
trap cleanup EXIT

bash lib/netlab.sh down 2>/dev/null
bash lib/netlab.sh up
ip netns exec benchpeer "$BIN/benchserver" >/tmp/srv.log 2>&1 &
srv_pid=$!
sleep 1
ip netns exec benchpeer ss -ltn 2>/dev/null | grep -qE ':9101' && echo "server listening (pid $srv_pid)" || { echo "SERVER DOWN"; cat /tmp/srv.log; exit 1; }

run_case() {
  local desc="$1"; shift
  bash lib/netlab.sh reset
  local out rc
  out=$(timeout 40 "$BIN/benchgen" "$@" 2>&1); rc=$?
  read -r eb ep ib ipk < <(bash lib/netlab.sh read)
  printf "[%-20s rc=%d]\n    %s\n    wire: egress=%s B/%s pkt  ingress=%s B/%s pkt\n" \
         "$desc" "$rc" "$out" "$eb" "$ep" "$ib" "$ipk"
}
run_case "TCP dl 10MiB"     -H 10.99.0.2 -t tcp  -d down -b 10485760
run_case "TCP ul 10MiB"     -H 10.99.0.2 -t tcp  -d up   -b 10485760
run_case "UDP dl 10MiB"     -H 10.99.0.2 -t udp  -d down -b 10485760
run_case "UDP ul 10MiB"     -H 10.99.0.2 -t udp  -d up   -b 10485760
run_case "SCTP dl 5MiB"     -H 10.99.0.2 -t sctp -d down -b 5242880
run_case "TCPv6 dl 5MiB"    -6 -H fd00:be0c::2 -t tcp -d down -b 5242880
run_case "sendfile ul 10MiB" -H 10.99.0.2 -t tcp -d up -m sendfile -b 10485760
run_case "sendmmsg UDP 10M" -H 10.99.0.2 -t udp -d up -m sendmmsg -b 10485760
run_case "low-and-slow 2MiB" -H 10.99.0.2 -t tcp -d up -r 1048576 -b 2097152
echo "=== all cases done ==="
