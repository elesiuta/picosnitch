#!/usr/bin/env bash
# Validate that the nft wire counter matches what a pcap tap on the interface
# sees (i.e. what nethogs/bandwhich/sniffnet capture), and that peer-side
# offloads are disabled. Also sums the captured frame (L2) bytes.
set -uo pipefail
cd "$(dirname "$0")/.."
BIN=./bin
srv_pid=""; td_pid=""
cleanup() { [ -n "$td_pid" ] && kill "$td_pid" 2>/dev/null; [ -n "$srv_pid" ] && kill "$srv_pid" 2>/dev/null; bash lib/netlab.sh down 2>/dev/null; }
trap cleanup EXIT
bash lib/netlab.sh down 2>/dev/null; bash lib/netlab.sh up
echo "=== peer-side (vbench1) offloads ==="
ip netns exec benchpeer ethtool -k vbench1 2>/dev/null | grep -E "^(tcp-segmentation-offload|generic-segmentation-offload|generic-receive-offload):"
ip netns exec benchpeer "$BIN"/benchserver >/tmp/srv.log 2>&1 &
srv_pid=$!; sleep 1

for spec in "tcp down 10485760" "tcp up 10485760" "udp down 10485760"; do
  set -- $spec; proto=$1; dir=$2; bytes=$3
  bash lib/netlab.sh reset
  # tcpdump on the host side of the veth = exactly where pcap monitors tap
  pcap=/tmp/gt_${proto}_${dir}.pcap
  tcpdump -i vbench0 -w "$pcap" -s0 "host 10.99.0.2" >/dev/null 2>&1 &
  td_pid=$!; sleep 0.4
  out=$(timeout 40 "$BIN"/benchgen -H 10.99.0.2 -t "$proto" -d "$dir" -b "$bytes" 2>&1)
  sleep 0.4; kill "$td_pid" 2>/dev/null; wait "$td_pid" 2>/dev/null; td_pid=""
  read -r eb ep ib ipk < <(bash lib/netlab.sh read)
  # sum captured frame bytes with tcpdump's own reader (-e prints the frame
  # length first; take only that one -- later "length" tokens are L4 payload)
  capframes=$(tcpdump -r "$pcap" -q -n 2>/dev/null | wc -l)
  capsum=$(tcpdump -nr "$pcap" -e 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="length"){s+=$(i+1); break}} END{print s+0}')
  printf "[%s %s]\n  gen: %s\n  nft wire: egress=%s/%spkt ingress=%s/%spkt\n  pcap(vbench0): frames=%s  frame_len_sum=%s\n" \
    "$proto" "$dir" "$out" "$eb" "$ep" "$ib" "$ipk" "$capframes" "$capsum"
done
