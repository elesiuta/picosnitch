# Per-process network & bandwidth monitors on Linux

<!-- --8<-- [start:findings] -->
<!-- --8<-- [start:overview] -->
A comparison of per-process (per-executable) network and bandwidth monitors on Linux, measuring **completeness** (is traffic seen and attributed to the right process) and **accuracy** (are the byte counts correct).

24 scenarios × 5 trials, each tool run in isolation on Ubuntu 26.04 (kernel 7.0) on a GCP e2-standard-4 (4 vCPUs, 16 GB), scored against independent ground truth. Detection = *seen and attributed to the right process*; Bandwidth = *bytes within ±10% (PASS) / ±25% (PARTIAL)* of the tool's measurement layer. Method, harness, and how to reproduce: [the `bench/` directory](https://github.com/elesiuta/picosnitch/tree/master/bench).

## Scoreboard

Each cell counts scenarios (of 24). N/A marks a capability a tool does not offer: opensnitch does no bandwidth accounting; the bcc tools and `bpftrace` hook TCP only. sniffnet has no per-process export, so its figures are read by OCR of its GUI and scored **best-of-5** — a scenario passes if any of its 5 trials passes; `*` marks cells where its trials disagreed — and it reports one combined per-program total, so the two full-duplex scenarios it cannot split by direction are N/A. The Flaky column counts scenarios whose 5 trials did not all agree.

| Tool | Detection: PASS / PART / FAIL / N-A | Bandwidth: PASS / PART / FAIL / N-A | Flaky |
|---|---|---|---|
| picosnitch | **23** / 0 / 1 / 0 | **23** / 0 / 1 / 0 | 0 |
| sysdig | **23** / 0 / 1 / 0 | **18** / 0 / 6 / 0 | 0 |
| little-snitch | **19** / 0 / 5 / 0 | **16** / 0 / 8 / 0 | 1 |
| opensnitch | **19** / 0 / 5 / 0 | **0** / 0 / 0 / 24 | 6 |
| sniffnet | **14** / 10 / 0 / 0 | **18** / 1 / 3 / 2 | 10 |
| bcc tcptop | **14** / 0 / 0 / 10 | **13** / 0 / 1 / 10 | 0 |
| bpftrace | **14** / 0 / 0 / 10 | **13** / 0 / 1 / 10 | 0 |
| bandwhich | **14** / 6 / 4 / 0 | **8** / 7 / 9 / 0 | 10 |
| nethogs | **11** / 10 / 3 / 0 | **16** / 1 / 7 / 0 | 3 |
| bcc | **11** / 3 / 0 / 10 | **14** / 0 / 0 / 10 | 1 |

## Resource usage

Each tool's whole process tree, sampled at 1 Hz across its session. CPU is % of one core (can exceed 100% across cores); p95 is the 95th percentile of the per-second samples. PSS (proportional set size) charges each shared page once, split across its sharers.

| Tool | CPU avg % | CPU p95 % | PSS avg MB | PSS peak MB |
|---|---|---|---|---|
| picosnitch | 1.2 | 2.9 | 46.6 | 47.5 |
| sysdig | 2.3 | 8.9 | 27.1 | 28.3 |
| little-snitch | 0.3 | 1.0 | 39.4 | 39.5 |
| opensnitch | 9.8 | 94.5 | 68.4 | 69.8 |
| sniffnet | 5.5 | 10.9 | 72.0 | 73.4 |
| bcc tcptop | 0.1 | 1.0 | 166.2 | 166.2 |
| bpftrace | 0.1 | 1.0 | 170.7 | 170.7 |
| bandwhich | 2.5 | 7.0 | 2.4 | 2.9 |
| nethogs | 0.7 | 2.0 | 9.0 | 9.7 |
| bcc | 0.1 | 0.0 | 277.2 | 277.3 |

<!-- --8<-- [end:overview] -->

## Per-scenario notes

- **s05 ICMP echo flood w/ payload** — ICMP is neither TCP nor UDP; monitors that only parse TCP/UDP miss it entirely.
- **s08 SCTP transfer** — SCTP is neither TCP nor UDP; TCP/UDP-only parsers miss it.
- **s10 Raw IP socket (proto 253) egress** — raw sockets with a custom IP protocol carry no TCP/UDP header; TCP/UDP-only attribution misses them.
- **s11 Short-lived processes** — /proc-scan attribution loses processes that exit before the next scan; their traffic lands in an unknown bucket.
- **s12 AF_PACKET raw-frame injection** — AF_PACKET hands complete L2 frames to the driver, bypassing the inet socket path, so socket- and syscall-layer monitors record nothing; pcap taps see the frames but have no /proc/net/{tcp,udp} entry to attribute them to a process.
- **s16 Loopback-only transfer** — traffic never leaves lo, which many monitors skip by default (nethogs needs -a; sniffnet must capture the lo adapter).

## Ground truth per scenario

App bytes are the generators' own counts. Wire bytes include per-run variance (handshakes, retransmits); this table shows one session's capture, and each tool page records its own run's values.

| # | Scenario | app bytes s/r | wire bytes s/r |
|---|---|---|---|
| s01 | TCP bulk download (control) | 24/33554432 | 46572/33608052 |
| s02 | TCP bulk upload | 33554456/0 | 34779428/45300 |
| s03 | TCP full-duplex up+down | 25165872/25165824 | 26122116/25239316 |
| s04 | UDP bulk up+down | 25166448/25165824 | 25669832/25669152 |
| s05 | ICMP echo flood w/ payload | 6342336/6468176 | 6468176/6468176 |
| s06 | QUIC-style UDP:443 bulk | 25166424/0 | 25669780/0 |
| s07 | IPv6 TCP transfer | 24/25165824 | 44960/25221632 |
| s08 | SCTP transfer | 24/25165824 | 424472/25572252 |
| s09 | DNS-style small UDP:53 flood | 4194328/0 | 6029364/0 |
| s10 | Raw IP socket (proto 253) egress | 4194304/0 | 4254224/0 |
| s11 | Short-lived processes | 10486240/0 | 10871408/49040 |
| s12 | AF_PACKET raw-frame injection | 4194304/0 | 4278192/0 |
| s13 | io_uring data path | 25165848/0 | 26081888/30740 |
| s14 | sendfile() zero-copy upload | 33554456/0 | 34779480/39060 |
| s15 | sendmmsg batched UDP | 25177624/0 | 25681204/0 |
| s16 | Loopback-only transfer | 24/25165824 | 24/25165824 |
| s17 | In-container (docker) egress | 25165848/0 | 26084644/30688 |
| s18 | Low-and-slow drip upload | 2097176/0 | 2173988/30532 |
| s19 | Many small TCP connections | 3933600/0 | 4093200/75256 |
| s20 | High-rate parallel burst | 7865040/0 | 8157364/46000 |
| s21 | io_uring download (recv) | 24/25165824 | 156240/25206288 |
| s22 | splice() zero-copy download | 24/33554432 | 72520/33608000 |
| s23 | recvmmsg batched UDP (recv) | 24/25165824 | 52/25669152 |
| s24 | IPv6 UDP download | 24/25165824 | 72/26028672 |
<!-- --8<-- [end:findings] -->
