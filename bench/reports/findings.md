# Per-process network & bandwidth monitors on Linux

<!-- --8<-- [start:findings] -->
<!-- --8<-- [start:overview] -->
A comparison of per-process (per-executable) network and bandwidth monitors on Linux, measuring **completeness** (is traffic seen and attributed to the right process) and **accuracy** (are the byte counts correct). Nine projects in ten configurations.

24 scenarios × 5 trials, each configuration run in isolation on Ubuntu 26.04 (kernel 7.0) on a GCP e2-standard-4 (4 vCPUs, 16 GB), run 2026-07-28, scored against tool-independent reference measurements. Detection = *seen and attributed to the right process*; Bandwidth = *bytes within ±10% (PASS) / ±25% (PARTIAL)* of the reference for the tool's layer. Method, harness, versions, and how to reproduce: [the `bench/` directory](https://github.com/elesiuta/picosnitch/tree/master/bench).

## Results summary

Each cell counts scenarios (of 24). N/A marks a missing capability: OpenSnitch does no bandwidth accounting; the BCC utilities and the bpftrace script used here hook TCP only; Sniffnet reports one combined per-program total, so the two full-duplex scenarios it cannot split by direction are N/A.

| Tool | Detection: PASS / PART / FAIL / N/A | Bandwidth: PASS / PART / FAIL / N/A | Trial disagreement |
|---|---|---|---|
| Sysdig | **24** / 0 / 0 / 0 | **19** / 0 / 5 / 0 | 0 |
| picosnitch | **23** / 0 / 1 / 0 | **23** / 0 / 1 / 0 | 0 |
| Little Snitch | **19** / 0 / 5 / 0 | **16** / 0 / 8 / 0 | 2 |
| OpenSnitch | **19** / 0 / 5 / 0 | **0** / 0 / 0 / 24 | 5 |
| BCC tcptop | **14** / 0 / 0 / 10 | **13** / 0 / 1 / 10 | 0 |
| bpftrace script | **14** / 0 / 0 / 10 | **13** / 0 / 1 / 10 | 0 |
| bandwhich | **14** / 6 / 4 / 0 | **7** / 7 / 10 / 0 | 10 |
| Sniffnet | **13** / 7 / 4 / 0 | **16** / 2 / 4 / 2 | 1 |
| NetHogs | **11** / 10 / 3 / 0 | **15** / 2 / 7 / 0 | 1 |
| BCC tcplife/tcpconnect | **11** / 3 / 0 / 10 | **14** / 0 / 0 / 10 | 0 |

## Versions

Read from each installed tool during the run. Pinned entries are built or downloaded at a fixed version by the harness; distro packages are whatever the Ubuntu archive shipped on the run date and are recorded, not pinned.

| Tool | Version observed | Source |
|---|---|---|
| Sysdig | 0.40.0 | distro package (recorded, not pinned) |
| picosnitch | 2.2.1 | pinned (PyPI via pipx) |
| Little Snitch | 1.0.9 | pinned (release .deb) |
| OpenSnitch | 1.8.0-1 | pinned (release .deb) |
| BCC tcptop | 0.37.0 | pinned (built from source tag) |
| bpftrace script | 0.25.0 | distro package (recorded, not pinned) |
| bandwhich | 0.23.1 | pinned (release binary) |
| Sniffnet | 1.5.1-1 | pinned (release .deb) |
| NetHogs | 0.9.0 | pinned (built from source tag) |
| BCC tcplife/tcpconnect | 0.37.0 | pinned (built from source tag) |

## Observed footprint

Each tool's whole process tree, sampled at 1 Hz across its session under its own capture scope; not a controlled performance comparison. CPU is % of one core (can exceed 100% across cores). PSS (proportional set size) charges each shared page once, split across its sharers.

| Tool | CPU mean % | CPU 95th pct % | PSS mean MB | PSS peak MB |
|---|---|---|---|---|
| Sysdig | 5.3 | 12.9 | 26.8 | 28.0 |
| picosnitch | 1.6 | 2.9 | 48.1 | 48.6 |
| Little Snitch | 0.3 | 1.0 | 39.5 | 39.5 |
| OpenSnitch | 12.1 | 100.3 | 68.9 | 71.7 |
| BCC tcptop | 0.1 | 1.0 | 167.5 | 167.5 |
| bpftrace script | 0.1 | 1.0 | 170.9 | 170.9 |
| bandwhich | 2.6 | 6.0 | 2.6 | 2.9 |
| Sniffnet | 5.1 | 20.0 | 68.9 | 79.3 |
| NetHogs | 0.7 | 2.0 | 6.8 | 7.2 |
| BCC tcplife/tcpconnect | 0.1 | 0.0 | 277.5 | 277.5 |

<!-- --8<-- [end:overview] -->

## Per-scenario notes

- **s05 ICMP echo flood w/ payload**: ICMP is neither TCP nor UDP; monitors that only parse TCP/UDP miss it entirely.
- **s08 SCTP transfer**: SCTP is neither TCP nor UDP; TCP/UDP-only parsers miss it.
- **s10 Raw IP socket (proto 253) egress**: raw sockets with a custom IP protocol carry no TCP/UDP header; TCP/UDP-only attribution misses them.
- **s11 Short-lived processes**: /proc-scan attribution loses processes that exit before the next scan; their traffic lands in an unknown bucket.
- **s12 AF_PACKET raw-frame injection**: AF_PACKET hands complete L2 frames to the driver, bypassing the INET socket path, so monitors hooking the INET socket functions record nothing; the writes are ordinary syscalls, so syscall tracing still sees them; pcap taps see the frames but have no /proc/net/{tcp,udp} entry to attribute them to a process.
- **s16 Loopback-only transfer**: traffic never leaves lo, which many monitors skip by default.

## Reference bytes per scenario

App bytes are the generators' own counts. Wire bytes include per-run variance (handshakes, retransmits); this table shows one session's capture, and each tool page records its own run's values.

| # | Scenario | app bytes s/r | wire bytes s/r |
|---|---|---|---|
| s01 | TCP bulk download (control) | 24/33554432 | 64096/33608108 |
| s02 | TCP bulk upload | 33554456/0 | 34779428/39944 |
| s03 | TCP full-duplex up+down | 25165872/25165824 | 26121440/25237964 |
| s04 | UDP bulk up+down | 25166448/25165824 | 25669832/25669152 |
| s05 | ICMP echo flood w/ payload | 6342336/6468176 | 6468176/6468176 |
| s06 | UDP/443 bulk | 25166424/0 | 25669780/0 |
| s07 | IPv6 TCP transfer | 24/25165824 | 47192/25221616 |
| s08 | SCTP transfer | 24/25165824 | 424472/25572252 |
| s09 | Small-packet UDP/53 flood | 4194328/0 | 6029364/0 |
| s10 | Raw IP socket (proto 253) egress | 4194304/0 | 4254224/0 |
| s11 | Short-lived processes | 10486240/0 | 10871460/43476 |
| s12 | AF_PACKET raw-frame injection | 4194304/0 | 4278192/0 |
| s13 | io_uring data path | 25165848/0 | 26083500/29388 |
| s14 | sendfile() zero-copy upload | 33554456/0 | 34779428/35992 |
| s15 | sendmmsg batched UDP | 25177624/0 | 25681204/0 |
| s16 | Loopback-only transfer | 24/25165824 | 24/25165824 |
| s17 | In-container (docker) egress | 25165848/0 | 26084644/41608 |
| s18 | Low-and-slow drip upload | 2097176/0 | 2173988/30272 |
| s19 | Many small TCP connections | 3933600/0 | 4093200/74788 |
| s20 | High-rate parallel burst | 7865040/0 | 8157884/53696 |
| s21 | io_uring download (recv) | 24/25165824 | 166016/25206132 |
| s22 | splice() zero-copy download | 24/33554432 | 85676/33608000 |
| s23 | recvmmsg batched UDP (recv) | 24/25165824 | 52/25669152 |
| s24 | IPv6 UDP download | 24/25165824 | 72/26028672 |
<!-- --8<-- [end:findings] -->
