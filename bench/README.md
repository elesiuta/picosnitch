# Per-process network & bandwidth monitor benchmark

A comparison of per-process (per-executable) network and bandwidth monitors on Linux, measuring **completeness** (is traffic seen and attributed to the right process) and **accuracy** (are the byte counts correct).
It generates known amounts of traffic across many protocols and hard-to-attribute cases, runs each monitor in isolation, and checks each monitor's output against an independent ground truth: whether it (a) **detected** the activity and attributed it to the right process, and (b) **measured** the right number of bytes.

## Tools under test

Environment: **Ubuntu 26.04, kernel 7.0** (7.0.0-1007-gcp) on a GCP **e2-standard-4** instance (4 vCPUs, 16 GB).
Each tool is installed at a **pinned version** the way its docs recommend (picosnitch from PyPI via pipx, *not* the source tree in this repo) using the latest releases as of July 2026, except bpftrace and sysdig, which are the Ubuntu 26.04 packages.
Each tool runs alone (no two monitors run at once).

| Tool | Pinned version | Measures | Extraction path |
| --- | --- | --- | --- |
| picosnitch | 2.2.1 (PyPI) | detection + bandwidth | SQLite `/var/lib/picosnitch/picosnitch.db` (`connections`) |
| opensnitch | 1.8.0 | detection only | connection log via journald (`journalctl -t opensnitch`) |
| bandwhich | 0.23.1 | bandwidth | `--raw --total-utilization` stdout |
| nethogs | 0.8.8 (build from src) | bandwidth | `-t -C -v 2 -a -d 1` trace stdout |
| sniffnet | 1.5.0 | detection + bandwidth¹ | GUI OCR under Xvfb (tesseract), + pcap flow-level fallback |
| little-snitch-linux | 1.0.9 | detection + bandwidth² | WebSocket `ws://localhost:3031/stream` (reverse-engineered) |
| bcc-tools (baseline) | 0.37.0 (upstream, built from src)³ | detection + TCP bandwidth | `tcplife`/`tcpconnect` stdout |
| bcc tcptop (baseline) | 0.37.0 (upstream) | TCP bandwidth | `tcptop -C 1` per-interval throughput (`tcp_sendmsg`/`tcp_cleanup_rbuf`) |
| bpftrace (baseline) | Ubuntu 26.04 package (0.25.0) | TCP bandwidth | ~10-line kprobe script on the same two hooks |
| sysdig | Ubuntu 26.04 package (0.40.0) | detection + bandwidth⁴ | syscall capture (`evt.rawres` summed over network I/O syscalls) |

¹ Sniffnet is a desktop GUI with no per-process export, so its per-process figures are read by OCR (tesseract) of its Overview "Program" panel, rendered headlessly under Xvfb.
OCR rounds figures to ~2 significant figures and can misread process names; scenarios where OCR cannot attribute fall back to flow level.
Xvfb and tesseract are Ubuntu 26.04 packages (unpinned).
² Little Snitch for Linux ships no documented export, but its web UI streams per-app connection rows + cumulative byte stats over a WebSocket, which the harness reads directly.
Because it attributes to the top-level responsible app, each generator is launched as its own detached transient systemd service, and the traffic history is cleared per run so names stay unique.
³ The Ubuntu package (bcc 0.35.0) fails to JIT-compile against the 7.0 kernel headers; upstream v0.37.0 built from source compiles and runs.
TCP-only, so non-TCP scenarios are N/A.
Included as an eBPF-tooling baseline.
⁴ sysdig watches syscalls rather than kernel socket functions.
It covers tcp/udp/icmp/raw (not AF_PACKET); the receive-path scenarios (io_uring/splice/recvmmsg) move bytes without the read/recv syscalls it counts, so it sees the process but not those bytes.

*Excluded* (per-interface / per-host only, no per-process attribution, so out of scope): iftop, vnstat, bmon, iptraf-ng, jnettop, tcptrack, pktstat, nload, ss, conntrack, standalone ntopng.

## Ground truth

Traffic crosses a **real interface** to a controlled peer in its own network namespace, over a veth pair — no external network, no CDN variance:

```
host (default netns)                       peer netns "benchpeer"
  vbench0  10.99.0.1 / fd00:be0c::1  <====>  vbench1 10.99.0.2 / fd00:be0c::2
```

Two independent references are captured for **every trial**, because different monitors measure at different layers:

* **Application bytes** — counted by the traffic generators themselves (exact); the reference for socket-layer monitors.
* **Wire bytes** — drop-free nftables counters in the peer namespace (which carries only benchmark traffic); the reference for pcap-layer monitors (payload + L3/L4 headers + retransmits).

Empirically the two references agree to within a few percent for bulk transfers; both are always reported.
Loopback and container scenarios use `lo` and docker respectively; AF_PACKET uses the generator's own byte count (it bypasses the socket layer by construction).

## Scoring

Each (tool × scenario) cell is **PASS / PARTIAL / FAIL / N/A**, decided from **5 trials** (configurable).
A footnote is attached to every PARTIAL and to any result that is **flaky** (detection/measurement not consistent across trials).

* **Detection** (was the activity seen and attributed to the right process?)
  * PASS — attributed to the correct executable in ≥ all-but-one trials.
  * PARTIAL — traffic seen but mis-/un-attributed (e.g. bucketed as "unknown").
  * FAIL — not seen at all.
* **Bandwidth** (reported bytes vs the reference for that tool's layer)
  * PASS — within **±10%** of the appropriate reference in ≥ all-but-one trials.
  * PARTIAL — within **±25%**, or right order of magnitude but attribution split.
  * FAIL — off by > ±25%, or zero.
  * The wire reference for pcap/AF_PACKET tools is the L3 nft count **plus one 14-byte Ethernet header per packet** (no FCS on the veth capture path), since those tools measure whole frames. This only matters for small-packet scenarios (e.g. S09), where the per-packet framing exceeds the ±10% band; it washes out (< 1%) for bulk transfers. Socket-layer tools are scored against the exact application byte count.
* **N/A** — the tool does not offer this capability (e.g. opensnitch has no bandwidth accounting; sniffnet has no per-process export).

Trials that disagree beyond one stray verdict resolve to the modal (most common) verdict, tie-broken toward the worse one, and the cell is flagged flaky (⚡).
Raw per-trial numbers and ratios are always recorded, so any threshold can be re-scored after the fact.

Each tool run begins with **control/smoke transfers in both directions** (bulk TCP download and upload, which every tool must pass — a bandwidth-capable tool reporting zero egress bytes on the upload also fails); a failed control invalidates that tool's run and is reported as a setup error rather than silently scoring the scenarios against a broken setup.

## Scenario catalog

Direction is from the host's perspective: **egress** = upload, **ingress** = download.
"Known amount" is the application-layer byte count each generator emits.

### Baseline / control
| # | Scenario | What it proves |
| --- | --- | --- |
| S01 | TCP bulk download (control) | everyone should PASS; validates setup |
| S02 | TCP bulk upload | egress accounting |
| S03 | TCP simultaneous full-duplex | tx/rx separated correctly |

### Protocol coverage (ingress/egress of every type)
| # | Scenario | What it probes |
| --- | --- | --- |
| S04 | UDP bulk down+up | UDP accounting in both directions |
| S05 | ICMP echo flood w/ payload | ICMP accounting (raw socket, not TCP/UDP) |
| S06 | "QUIC-style" UDP:443 bulk | encrypted-UDP handling |
| S07 | IPv6 TCP transfer | IPv6 support/attribution |
| S08 | SCTP transfer | SCTP accounting (not TCP/UDP) |
| S09 | DNS-style small UDP:53 flood | many tiny UDP packets |
| S10 | Raw IP socket (proto 253) egress | non-TCP/UDP protocol number |

### Attribution stressors (hard-to-attribute traffic)
| # | Scenario | What it probes |
| --- | --- | --- |
| S11 | Short-lived processes (connect+send+exit ×N) | attribution of processes that exit quickly |
| S12 | AF_PACKET raw frame injection | L2 injection that bypasses the socket layer |
| S13 | io_uring data path | transfer via io_uring rather than send/recv syscalls |
| S14 | sendfile() zero-copy upload | zero-copy send (post-`sendpage` path) |
| S15 | sendmmsg batched UDP (send) | batched send syscall (recv counterpart in S23) |
| S16 | Loopback-only transfer | traffic over `lo` (off the default interface) |
| S17 | In-container (docker) egress | attribution across a container boundary |
| S18 | Low-and-slow drip upload | totals over a long low-rate transfer |

### Bandwidth accuracy stressors
| # | Scenario | What it probes |
| --- | --- | --- |
| S19 | Many small TCP transfers | payload-vs-wire gap; many-connection accuracy |
| S20 | High-rate burst (many parallel conns) | behavior under dropped events / packets |

### Ingress counterparts (receive-path coverage)
The technique scenarios above are almost all egress; the receive path goes through different kernel functions than send.
| # | Scenario | What it probes |
| --- | --- | --- |
| S21 | io_uring download (recv) | receive via io_uring rather than read/recv syscalls |
| S22 | splice() zero-copy download | zero-copy receive via `splice()` (`tcp_splice_read`) |
| S23 | recvmmsg batched UDP (recv) | batched receive syscall (recv counterpart of S15) |
| S24 | IPv6 UDP download | IPv6 × UDP receive |

S12 (AF_PACKET) injects L2 frames that bypass the socket layer entirely.
It is scored by tool layer: **socket/syscall-layer monitors that cannot see it (picosnitch, little-snitch, sysdig) score FAIL**; the **TCP-only baselines (bcc, bpftrace) score N/A**, consistent with their N/A on every other non-TCP scenario; **pcap/wire tools (nethogs, sniffnet) do see the frames** and score on whether they attribute them.
AF_PACKET needs CAP_NET_RAW (root) to send.

## Resource usage

`lib/run.py` profiles each tool's whole process tree at 1 Hz across its session (`lib/resprof.py`; disable with `--no-profile`).
The report shows avg + p95 CPU% and avg/peak PSS memory per tool — `/proc` sampling, not a controlled micro-benchmark.

## Reproducibility

* Tool versions are pinned in `lib/adapters.py` (per-tool `install()`).
* All traffic is synthetic and local (netns peer) — no internet dependency.
* Every scenario runs **N=5 trials**; variance is flagged.
* Generators print exact byte counts; ground truth is captured per trial.

## Layout

```
bench/
  gen/       C traffic generators + peer server (source)
  bin/       compiled helpers (build with lib/build.sh)
  lib/       adapters (install/start/collect/stop per tool), scenarios,
             netlab (netns+veth+nft ground truth), runner, resource profiler,
             standalone smoke / ground-truth validation scripts
  results/   per-run artifacts (raw results.json + OCR pcap/png); not committed,
             regenerated by running the matrix — the generated reports/ are the record
  reports/   generated markdown scorecards + findings
  notes/     research notes per tool
```

## Running

On Ubuntu 26.04 (kernel 7.0):

```sh
sudo bash lib/build.sh                  # compile helpers
sudo python3 lib/run.py --tools all     # install, run matrix, score, report
```
