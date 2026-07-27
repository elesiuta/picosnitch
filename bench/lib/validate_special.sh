#!/usr/bin/env bash
# Validate the specialized generators (icmp, raw-IP, AF_PACKET, io_uring)
# against the nft wire ground truth. Run as root.
set -uo pipefail
cd "$(dirname "$0")/.."
srv_pid=""
cleanup() { [ -n "$srv_pid" ] && kill "$srv_pid" 2>/dev/null; bash lib/netlab.sh down 2>/dev/null; }
trap cleanup EXIT
bash lib/netlab.sh down 2>/dev/null; bash lib/netlab.sh up
ip netns exec benchpeer ./bin/benchserver >/tmp/srv.log 2>&1 &
srv_pid=$!; sleep 1
PEERMAC=$(ip netns exec benchpeer cat /sys/class/net/vbench1/address)
echo "peer vbench1 mac = $PEERMAC"

show() {
  local desc="$1"; shift
  bash lib/netlab.sh reset
  local out rc
  out=$(timeout 40 "$@" 2>&1); rc=$?
  read -r eb ep ib ipk < <(bash lib/netlab.sh read)
  printf "[%-16s rc=%d]\n  %s\n  wire: egress=%s B/%s pkt  ingress=%s B/%s pkt\n" \
    "$desc" "$rc" "$out" "$eb" "$ep" "$ib" "$ipk"
}
show "ICMP 4MiB"    ./bin/benchicmp -H 10.99.0.2 -b 4194304 -s 1000
show "raw-IP 4MiB"  ./bin/benchraw  -H 10.99.0.2 -b 4194304 -p 253
show "AF_PACKET 4M" ./bin/benchpacket -i vbench0 -S 10.99.0.1 -D 10.99.0.2 -M "$PEERMAC" -b 4194304
show "io_uring dl 10M" ./bin/benchuring -H 10.99.0.2 -d down -b 10485760
show "io_uring ul 10M" ./bin/benchuring -H 10.99.0.2 -d up   -b 10485760
echo "=== done ==="
