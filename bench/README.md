# Per-process network & bandwidth monitor benchmark

A comparison of per-process (per-executable) network and bandwidth monitors on Linux, measuring **completeness** (is traffic seen and attributed to the right process) and **accuracy** (are the byte counts correct).
It generates known amounts of traffic across many protocols and hard-to-attribute cases, runs each configuration in isolation, and checks the output against tool-independent reference measurements: whether it (a) **detected** the activity and attributed it to the right process, and (b) **measured** the right number of bytes.

Nine projects are covered in ten configurations.

## Tools under test

Environment: **Ubuntu 26.04, kernel 7.0** on a GCP **e2-standard-4** instance (4 vCPUs, 16 GB).
Each configuration runs alone.

Versions are read from each installed tool during the run and published in the Versions table of the generated report.
Pinned versions are set in `lib/adapters.py`; Ubuntu package versions are whatever the archive ships on the run date, and are recorded rather than pinned.
picosnitch is installed from PyPI, not from the source tree in this repository.

| Tool | Install | Extraction path |
| --- | --- | --- |
| picosnitch | pinned (PyPI via pipx) | SQLite `/var/lib/picosnitch/picosnitch.db` (`connections`) |
| OpenSnitch | pinned (release .deb) | connection log via journald (`journalctl -t opensnitch`) |
| bandwhich | pinned (release binary) | `--raw --total-utilization --no-resolve` stdout |
| NetHogs | pinned (built from source) | `-t -C -v 2 -a -d 1 vbench0 lo` trace stdout |
| Sniffnet¹ | pinned (release .deb) | GUI OCR under Xvfb (tesseract) |
| Little Snitch² | pinned (release .deb) | local WebSocket `ws://localhost:3031/stream` |
| BCC `tcplife`/`tcpconnect` | pinned (built from source)³ | `tcplife`/`tcpconnect` stdout |
| BCC `tcptop` | pinned (built from source) | `tcptop -C 1` per-interval throughput (`tcp_sendmsg`/`tcp_cleanup_rbuf`) |
| bpftrace script | Ubuntu package, recorded | a `bpftrace -e` program in `lib/adapters.py`, on the same two hooks |
| Sysdig⁴ | Ubuntu package, recorded | syscall capture (`evt.rawres` summed over network I/O syscalls) |

¹ Sniffnet is a desktop GUI with no per-process export, so its per-process figures are read by OCR (tesseract) of its Overview "Program" panel, rendered headlessly under Xvfb.
Sniffnet lists traffic it cannot attribute under a `?` row; that row is read as its unattributed bucket, like the unknown buckets of the other wire-layer tools.
It is restarted before each trial, so the panel lists only that trial's traffic and a row cannot be pushed out of view.
Only what Sniffnet itself displays is scored; a scenario it does not list is scored as reported-nothing, like any other tool.
² Little Snitch's web UI is driven by an undocumented local WebSocket, which the harness reads directly for per-app connection rows and cumulative byte statistics.
It attributes traffic to the top-level responsible application, so each generator is launched as its own detached transient systemd service, and the traffic history is cleared per run so names stay unique.
³ The Ubuntu package fails to compile its programs against the 7.0 kernel headers; the pinned upstream build compiles and runs.
These utilities hook TCP only, so non-TCP scenarios are N/A.
⁴ Sysdig traces syscalls rather than kernel socket functions.
Because packet-socket writes are ordinary `sendto`/`sendmsg` syscalls, it sees AF_PACKET traffic that INET socket-hook monitors miss; its filter matches INET sockets by `fd.type` and packet sockets by syscall name.
Scenarios that move bytes without the send/recv syscalls it counts (io_uring in either direction, `sendfile()`, `splice()`) show the process but not those bytes.

*Excluded* (per-interface or per-host only, no per-process attribution, so out of scope): iftop, vnstat, bmon, iptraf-ng, jnettop, tcptrack, pktstat, nload, conntrack, standalone ntopng.

## Reference measurements

Traffic crosses a **real interface** to a controlled peer in its own network namespace, over a veth pair, with no external network and no CDN variance:

```
host (default netns)                       peer netns "benchpeer"
  vbench0  10.99.0.1 / fd00:be0c::1  <====>  vbench1 10.99.0.2 / fd00:be0c::2
```

Two references, independent of the tools under test, are captured for **every trial**, because different monitors measure at different layers:

* **Application bytes**: counted by the traffic generators themselves (exact); the reference for socket-layer monitors.
* **Wire bytes**: dedicated nftables counters in the peer namespace, which carries only benchmark traffic; the reference for pcap-layer monitors (payload plus L3/L4 headers plus retransmits).


## Scoring

Each (tool × scenario) cell is **PASS / PARTIAL / FAIL / N/A**, decided from **5 trials** (configurable).
A footnote is attached to every PARTIAL or FAIL and to any cell whose trials did not all agree.

* **Detection** (was the activity seen and attributed to the right process?)
  * PASS: attributed to the correct executable.
  * PARTIAL: traffic seen but mis-attributed or unattributed (for example bucketed as "unknown").
  * FAIL: not seen at all.
* **Bandwidth** (reported bytes against the reference for that tool's layer)
  * PASS: within **±10%** of the appropriate reference.
  * PARTIAL: within **±25%**.
  * FAIL: outside **±25%**.
  * The wire reference for pcap and AF_PACKET tools is the L3 nftables count **plus one 14-byte Ethernet header per packet** (no FCS on the veth capture path), since those tools measure whole frames. This only matters for small-packet scenarios such as s09, where the per-packet framing exceeds the ±10% band; it washes out (< 1%) for bulk transfers. Socket-layer tools are scored against the exact application byte count.
* **N/A**: the tool does not offer this capability.

A cell passes without disagreement when all trials pass; otherwise it takes the modal (most common) verdict, tie-broken toward the worse one.
Any cell whose trials did not all agree is marked `*` to indicate disagreement between trials.

Each tool run begins with **control transfers in both directions** (bulk TCP download and upload, which every tool must pass; a bandwidth-capable tool reporting zero egress bytes on the upload also fails).
A failed control invalidates that tool's run.

## Scenario catalog

Direction is from the host's perspective: **egress** = upload, **ingress** = download.

### Baseline / control
| # | Scenario | What it checks |
| --- | --- | --- |
| s01 | TCP bulk download (control) | validates setup |
| s02 | TCP bulk upload | egress accounting |
| s03 | TCP full-duplex up+down | tx/rx separated correctly |

### Protocol coverage (ingress/egress of every type)
| # | Scenario | What it checks |
| --- | --- | --- |
| s04 | UDP bulk up+down | UDP accounting in both directions |
| s05 | ICMP echo flood w/ payload | ICMP accounting (raw socket, not TCP/UDP) |
| s06 | UDP/443 bulk | UDP egress on port 443 |
| s07 | IPv6 TCP transfer | IPv6 support/attribution |
| s08 | SCTP transfer | SCTP accounting (not TCP/UDP) |
| s09 | Small-packet UDP/53 flood | many small UDP packets |
| s10 | Raw IP socket (proto 253) egress | non-TCP/UDP protocol number |

### Attribution stressors (hard-to-attribute traffic)
| # | Scenario | What it checks |
| --- | --- | --- |
| s11 | Short-lived processes | attribution of processes that exit quickly |
| s12 | AF_PACKET raw-frame injection | L2 injection that bypasses the INET socket path |
| s13 | io_uring data path | transfer via io_uring rather than send/recv syscalls |
| s14 | sendfile() zero-copy upload | zero-copy send (post-`sendpage` path) |
| s15 | sendmmsg batched UDP | batched send syscall (recv counterpart in s23) |
| s16 | Loopback-only transfer | traffic over `lo` (off the default interface) |
| s17 | In-container (docker) egress | attribution across a container boundary |
| s18 | Low-and-slow drip upload | totals over a long low-rate transfer |

### Bandwidth accuracy stressors
| # | Scenario | What it checks |
| --- | --- | --- |
| s19 | Many small TCP connections | payload-vs-wire gap; many-connection accuracy |
| s20 | High-rate parallel burst | accounting during a high-rate burst |

### Ingress counterparts (receive-path coverage)
| # | Scenario | What it checks |
| --- | --- | --- |
| s21 | io_uring download (recv) | receive via io_uring rather than read/recv syscalls |
| s22 | splice() zero-copy download | zero-copy receive via `splice()` (`tcp_splice_read`) |
| s23 | recvmmsg batched UDP (recv) | batched receive syscall (recv counterpart of s15) |
| s24 | IPv6 UDP download | IPv6 × UDP receive |

## Observed footprint

`lib/run.py` profiles each tool's whole process tree at 1 Hz across its session (`lib/resprof.py`; disable with `--no-profile`).

## Layout

```
bench/
  gen/       C traffic generators + peer server (source)
  bin/       compiled helpers (build with lib/build.sh)
  lib/       adapters (install/start/collect/stop per tool), scenarios,
             netlab (netns+veth+nft reference counters), runner, resource profiler,
             standalone smoke / reference validation scripts
  results/   per-run artifacts (raw results.json + OCR pcap/png); not committed,
             regenerated by running the matrix, the generated reports/ are the record
  reports/   generated markdown scorecards + findings
```

## Running

On Ubuntu 26.04 (kernel 7.0):

```sh
sudo bash lib/build.sh                  # compile helpers
sudo python3 lib/run.py --tools all     # install, run matrix, score, report
```
