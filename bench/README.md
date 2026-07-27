# Per-process network & bandwidth monitor benchmark

A comparison of per-process (per-executable) network and bandwidth monitors on Linux, measuring **completeness** (is traffic seen and attributed to the right process) and **accuracy** (are the byte counts correct).
It generates known amounts of traffic across many protocols and hard-to-attribute cases, runs each configuration in isolation, and checks the output against tool-independent reference measurements: whether it (a) **detected** the activity and attributed it to the right process, and (b) **measured** the right number of bytes.

Nine projects are covered in ten configurations (BCC contributes two: `tcplife`/`tcpconnect` and `tcptop`).

## Tools under test

Environment: **Ubuntu 26.04, kernel 7.0** (7.0.0-1007-gcp) on a GCP **e2-standard-4** instance (4 vCPUs, 16 GB).
Each configuration runs alone; no two monitors run at once.

Versions are read from each installed tool during the run and published in the Versions table of the generated report, so that table is the authoritative record of what was measured.
The harness pins picosnitch, OpenSnitch, bandwhich, NetHogs, Sniffnet, Little Snitch and BCC to fixed versions (built from a source tag, or a release download) in `lib/adapters.py`.
bpftrace and Sysdig are Ubuntu packages: their versions are whatever the archive ships on the run date, and are recorded rather than pinned.
picosnitch is installed from PyPI via pipx, not from the source tree in this repository.

| Tool | Version | Measures | Extraction path |
| --- | --- | --- | --- |
| picosnitch | 2.2.1, pinned (PyPI) | detection + bandwidth | SQLite `/var/lib/picosnitch/picosnitch.db` (`connections`) |
| OpenSnitch | 1.8.0, pinned | detection only | connection log via journald (`journalctl -t opensnitch`) |
| bandwhich | 0.23.1, pinned | bandwidth | `--raw --total-utilization` stdout |
| NetHogs | 0.9.0, pinned (built from source) | bandwidth | `-t -C -v 2 -a -d 1` trace stdout |
| Sniffnet | 1.5.1, pinned | detection + bandwidth¹ | GUI OCR under Xvfb (tesseract), plus a pcap flow-level fallback |
| Little Snitch for Linux | 1.0.9, pinned | detection + bandwidth² | local WebSocket `ws://localhost:3031/stream` |
| BCC `tcplife`/`tcpconnect` | 0.37.0, pinned (built from source)³ | detection + TCP bandwidth | `tcplife`/`tcpconnect` stdout |
| BCC `tcptop` | 0.37.0, pinned (built from source) | TCP bandwidth | `tcptop -C 1` per-interval throughput (`tcp_sendmsg`/`tcp_cleanup_rbuf`) |
| bpftrace script | Ubuntu package, recorded | TCP bandwidth | a ~10-line kprobe script in this repository, on the same two hooks |
| Sysdig | Ubuntu package, recorded | detection + bandwidth⁴ | syscall capture (`evt.rawres` summed over network I/O syscalls) |

¹ Sniffnet is a desktop GUI with no per-process export, so its per-process figures are read by OCR (tesseract) of its Overview "Program" panel, rendered headlessly under Xvfb.
OCR rounds figures to about two significant figures and can misread process names, so Sniffnet alone is scored best of 5 trials.
Where OCR cannot attribute a scenario, the result falls back to flow level, measured by a parallel tcpdump capture rather than read from Sniffnet; such results are marked PARTIAL and the note records the provenance.
Xvfb and tesseract are Ubuntu packages.
² Little Snitch for Linux ships no documented export. Its web UI is driven by an undocumented local WebSocket, which the harness reads directly for per-app connection rows and cumulative byte statistics.
It attributes traffic to the top-level responsible application, so each generator is launched as its own detached transient systemd service, and the traffic history is cleared per run so names stay unique.
³ The Ubuntu package (BCC 0.35.0) fails to compile its programs against the 7.0 kernel headers; upstream v0.37.0 built from source compiles and runs.
These utilities hook TCP only, so non-TCP scenarios are N/A.
Included as an eBPF-tooling baseline.
⁴ Sysdig traces syscalls rather than kernel socket functions.
Because packet-socket writes are ordinary `sendto`/`sendmsg` syscalls, it sees AF_PACKET traffic that INET socket-hook monitors miss; its filter matches INET sockets by `fd.type` and packet sockets by syscall name.
Scenarios that move bytes without the send/recv syscalls it counts (io_uring in either direction, `sendfile()`, `splice()`, and the batched `recvmmsg` receive) show the process but not those bytes.

*Excluded* (per-interface or per-host only, no per-process attribution, so out of scope): iftop, vnstat, bmon, iptraf-ng, jnettop, tcptrack, pktstat, nload, ss, conntrack, standalone ntopng.

## Reference measurements

Traffic crosses a **real interface** to a controlled peer in its own network namespace, over a veth pair, with no external network and no CDN variance:

```
host (default netns)                       peer netns "benchpeer"
  vbench0  10.99.0.1 / fd00:be0c::1  <====>  vbench1 10.99.0.2 / fd00:be0c::2
```

Two references, independent of the tools under test, are captured for **every trial**, because different monitors measure at different layers:

* **Application bytes**: counted by the traffic generators themselves (exact); the reference for socket-layer monitors.
* **Wire bytes**: dedicated nftables counters in the peer namespace, which carries only benchmark traffic; the reference for pcap-layer monitors (payload plus L3/L4 headers plus retransmits).

Empirically the two references agree to within a few percent for bulk transfers; both are always reported.
Loopback and container scenarios use `lo` and docker respectively; AF_PACKET uses the generator's own byte count, since it bypasses the socket layer by construction.

## Scoring

Each (tool × scenario) cell is **PASS / PARTIAL / FAIL / N/A**, decided from **5 trials** (configurable).
A footnote is attached to every PARTIAL and to any cell whose trials did not all agree.

* **Detection** (was the activity seen and attributed to the right process?)
  * PASS: attributed to the correct executable in at least four of five trials.
  * PARTIAL: traffic seen but mis-attributed or unattributed (for example bucketed as "unknown").
  * FAIL: not seen at all.
* **Bandwidth** (reported bytes against the reference for that tool's layer)
  * PASS: within **±10%** of the appropriate reference in at least four of five trials.
  * PARTIAL: within **±25%**, or right order of magnitude but attribution split.
  * FAIL: outside **±25%**, or zero.
  * The wire reference for pcap and AF_PACKET tools is the L3 nftables count **plus one 14-byte Ethernet header per packet** (no FCS on the veth capture path), since those tools measure whole frames. This only matters for small-packet scenarios such as S09, where the per-packet framing exceeds the ±10% band; it washes out (< 1%) for bulk transfers. Socket-layer tools are scored against the exact application byte count.
* **N/A**: the configuration does not offer this capability (for example OpenSnitch has no bandwidth accounting, and Sniffnet cannot split a full-duplex total by direction).

The two axes are scored independently. Bandwidth measures the bytes a configuration reported for the traffic, whether or not it named the process; where it measured the traffic but bucketed it as unknown, those bytes are still scored on the bandwidth axis and the attribution miss is recorded as PARTIAL on the detection axis. A bandwidth PASS beside a detection PARTIAL therefore means the bytes were right but the process was not identified.

Trials that disagree beyond one stray verdict resolve to the modal (most common) verdict, tie-broken toward the worse one, and the cell is marked as disagreeing (⚡).
Sniffnet is the one exception: because GUI OCR is unreliable, its cells are scored best of 5 trials, marked `*`.
Raw per-trial numbers and ratios are always recorded, so any threshold can be re-scored after the fact.

Each tool run begins with **control transfers in both directions** (bulk TCP download and upload, which every tool must pass; a bandwidth-capable tool reporting zero egress bytes on the upload also fails).
A failed control invalidates that tool's run and is reported as a setup error rather than silently scoring the scenarios against a broken setup.

## Scenario catalog

Direction is from the host's perspective: **egress** = upload, **ingress** = download.
"Known amount" is the application-layer byte count each generator emits.

### Baseline / control
| # | Scenario | What it checks |
| --- | --- | --- |
| S01 | TCP bulk download (control) | everyone should PASS; validates setup |
| S02 | TCP bulk upload | egress accounting |
| S03 | TCP simultaneous full-duplex | tx/rx separated correctly |

### Protocol coverage (ingress/egress of every type)
| # | Scenario | What it checks |
| --- | --- | --- |
| S04 | UDP bulk down+up | UDP accounting in both directions |
| S05 | ICMP echo flood with payload | ICMP accounting (raw socket, not TCP/UDP) |
| S06 | UDP/443 bulk | bulk UDP egress on a port commonly carrying QUIC |
| S07 | IPv6 TCP transfer | IPv6 support/attribution |
| S08 | SCTP transfer | SCTP accounting (not TCP/UDP) |
| S09 | Small-packet UDP/53 flood | many small UDP packets |
| S10 | Raw IP socket (proto 253) egress | non-TCP/UDP protocol number |

### Attribution stressors (hard-to-attribute traffic)
| # | Scenario | What it checks |
| --- | --- | --- |
| S11 | Short-lived processes (connect+send+exit ×N) | attribution of processes that exit quickly |
| S12 | AF_PACKET raw frame injection | L2 injection that bypasses the INET socket path |
| S13 | io_uring data path | transfer via io_uring rather than send/recv syscalls |
| S14 | sendfile() zero-copy upload | zero-copy send (post-`sendpage` path) |
| S15 | sendmmsg batched UDP (send) | batched send syscall (recv counterpart in S23) |
| S16 | Loopback-only transfer | traffic over `lo` (off the default interface) |
| S17 | In-container (docker) egress | attribution across a container boundary |
| S18 | Low-and-slow drip upload | totals over a long low-rate transfer |

### Bandwidth accuracy stressors
| # | Scenario | What it checks |
| --- | --- | --- |
| S19 | Many small TCP transfers | payload-vs-wire gap; many-connection accuracy |
| S20 | High-rate burst (many parallel conns) | accounting during a high-rate burst |

### Ingress counterparts (receive-path coverage)
The technique scenarios above are almost all egress; the receive path goes through different kernel functions than send.
| # | Scenario | What it checks |
| --- | --- | --- |
| S21 | io_uring download (recv) | receive via io_uring rather than read/recv syscalls |
| S22 | splice() zero-copy download | zero-copy receive via `splice()` (`tcp_splice_read`) |
| S23 | recvmmsg batched UDP (recv) | batched receive syscall (recv counterpart of S15) |
| S24 | IPv6 UDP download | IPv6 × UDP receive |

S12 (AF_PACKET) hands the kernel complete L2 frames, bypassing the INET socket path.
Monitors that hook the INET socket functions therefore record nothing, while syscall tracing still sees the writes, since a packet socket is written with ordinary `sendto`/`sendmsg` calls, and pcap tools see the frames on the wire and score on whether they attribute them.
The TCP-only BCC and bpftrace baselines are N/A, consistent with their N/A on every other non-TCP scenario.
Sending on an AF_PACKET socket requires CAP_NET_RAW.

## Observed footprint

`lib/run.py` profiles each tool's whole process tree at 1 Hz across its session (`lib/resprof.py`; disable with `--no-profile`).
The report shows the mean and 95th percentile CPU and the mean and peak PSS memory per configuration.
This is `/proc` sampling of each tool as configured here, including differing capture scopes and filters, not a controlled cross-tool performance comparison.

## Reproducibility

* Pinned versions are set in `lib/adapters.py` (per-tool `install()`); distro-package versions are recorded from the installed tool at run time.
* All traffic is synthetic and local (netns peer), with no internet dependency.
* Every scenario runs **N=5 trials**; trials that disagree are marked.
* Generators print exact byte counts; reference measurements are captured per trial.

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
