#!/usr/bin/env bash
# Clean slate + run the full benchmark matrix. Run via:
#   sudo nohup bash lib/launch_matrix.sh > /tmp/fullmatrix.log 2>&1 &
cd "$(dirname "$0")/.."
pkill -9 -x bandwhich 2>/dev/null
pkill -9 -x nethogs 2>/dev/null
pkill -9 -f "sniffnet|Xvfb|tcplife|tcpconnect|benchserver|tcpdump" 2>/dev/null
pkill -9 -f "bcc/tools/tcptop|bpftrace -e|sysdig -p|import -window" 2>/dev/null
pkill -9 -f "/opt/bench/run/" 2>/dev/null
systemctl stop picosnitch opensnitch littlesnitch 2>/dev/null
systemctl stop 'lsbench*' 2>/dev/null
# apt timers must not install anything mid-run: recorded distro versions must hold
systemctl stop apt-daily.timer apt-daily-upgrade.timer unattended-upgrades 2>/dev/null
ip netns del benchpeer 2>/dev/null
ip link del vbench0 2>/dev/null
rm -rf results/*
exec python3 lib/run.py --tools all --scenarios all --trials 5
