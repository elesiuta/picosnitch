#!/usr/bin/env bash
# Clean slate + run the full benchmark matrix. Run via:
#   sudo nohup bash lib/launch_matrix.sh > /tmp/fullmatrix.log 2>&1 &
cd "$(dirname "$0")/.."
pkill -9 -x bandwhich 2>/dev/null
pkill -9 -x nethogs 2>/dev/null
pkill -9 -f "sniffnet|xvfb|tcplife|tcpconnect|benchserver|tcpdump" 2>/dev/null
systemctl stop picosnitch opensnitch 2>/dev/null
ip netns del benchpeer 2>/dev/null
ip link del vbench0 2>/dev/null
rm -rf results/*
exec python3 lib/run.py --tools all --scenarios all --trials 5
