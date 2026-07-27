# OpenSnitch — benchmark notes

- **Pinned version:** v1.8.0 (2025-12-15). Install the daemon `.deb` (`opensnitch_1.8.0-1_amd64.deb`).
- **Measures:** **detection only** — it is an application firewall, not a bandwidth meter. All bandwidth cells are **N/A**.
- Runs fully headless: shipped `DefaultAction: allow` means with no GUI attached it allows-and-logs (never blocks). eBPF process attribution loads and works on kernel 7.0 (verified it attributes PID + PATH correctly).

## Headless extraction (as actually observed on this box)
- The daemon logs **every intercepted connection to syslog → journald** under identifier `opensnitch`, in a bracketed format:
  ```
  CONNECTION - [SRC="10.99.0.1" SPT="…" DST="10.99.0.2" DSTHOST="…" DPT="9101"
                PROTO="tcp" PID="…" UID="0" PATH="/opt/bench/run/bg_tcp_dl.7" CMDLINE="…" …]
  ```
  - Read with `journalctl -t opensnitch -o cat --since @<t0> --until @<t1>`.
  - Match our unique executable in `PATH="…"`; the destination/port are also present for a flow-level fallback.
  - (The documented JSON SIEM logger config did not take effect in v1.8.0 on this box — the bracketed syslog line is the reliable machine-readable source.)
- One record per `connect()`/new flow; attribution includes the full process tree.

## Coverage
- Detects **TCP, UDP (v4/v6, UDPLITE), ICMP** via NFQUEUE + eBPF kprobes.
- **AF_PACKET** raw injection bypasses netfilter's OUTPUT path → opensnitch does **not** see it (like picosnitch, but for a different reason). (s12)
- **SCTP / raw IP** use `sctp_sendmsg` / `raw_sendmsg`, which opensnitch's eBPF (hooking `tcp_v*_connect` / `udp*_sendmsg`) does not cover → typically missed. (s08, s10)

## Run interactions observed
- In the recorded matrix, the s10 raw-IP generator stalled early under opensnitch (app GT ≈0.27 MB vs 4 MB in other tools' sessions; benchraw stops at the first send error), and the s09 wire counter under-read. Neither affects opensnitch's scores: s10 detection is FAIL on 0 matched records, and bandwidth is N/A throughout.

## Lifecycle
- `systemctl start|stop opensnitch`. Creates its own nft table `opensnitch`; `QueueBypass:true` fails open if the daemon dies.
