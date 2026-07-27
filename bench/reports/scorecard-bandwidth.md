# Bandwidth scorecard — *are the bytes measured accurately (±10% PASS / ±25% PARTIAL)?*

<!-- --8<-- [start:grid] -->
## Bandwidth accuracy

| # | Scenario | picosnitch | nethogs | bandwhich | opensnitch | sniffnet | little-snitch | bcc | bcc tcptop | bpftrace | sysdig |
|---|---|---|---|---|---|---|---|---|---|---|---|
| s01 | TCP bulk download (control) | ✅ | ✅ | ✅⚡ | ⬜ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| s02 | TCP bulk upload | ✅ | ✅ | 🟡⚡ | ⬜ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| s03 | TCP full-duplex up+down | ✅ | ✅ | ✅⚡ | ⬜ | ⬜ | ✅ | ✅⚡ | ✅ | ✅ | ✅ |
| s04 | UDP bulk up+down | ✅ | ✅ | ✅ | ⬜ | ⬜ | ✅ | ⬜ | ⬜ | ⬜ | ✅ |
| s05 | ICMP echo flood w/ payload | ✅ | ❌ | ❌ | ⬜ | ✅ | ❌ | ⬜ | ⬜ | ⬜ | ✅ |
| s06 | QUIC-style UDP:443 bulk | ✅ | ✅ | 🟡 | ⬜ | ✅* | ✅ | ⬜ | ⬜ | ⬜ | ✅ |
| s07 | IPv6 TCP transfer | ✅ | ✅ | 🟡⚡ | ⬜ | ✅* | ✅ | ✅ | ✅ | ✅ | ✅ |
| s08 | SCTP transfer | ✅ | ❌ | ❌ | ⬜ | 🟡* | ✅ | ⬜ | ⬜ | ⬜ | ✅ |
| s09 | DNS-style small UDP:53 flood | ✅ | ✅ | ❌ | ⬜ | ✅* | ❌ | ⬜ | ⬜ | ⬜ | ✅ |
| s10 | Raw IP socket (proto 253) egress | ✅ | ❌ | ❌ | ⬜ | ❌ | ❌ | ⬜ | ⬜ | ⬜ | ✅ |
| s11 | Short-lived processes | ✅ | ❌ | 🟡 | ⬜ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| s12 | AF_PACKET raw-frame injection | ❌ | ✅ | ✅⚡ | ⬜ | ✅ | ❌ | ⬜ | ⬜ | ⬜ | ❌ |
| s13 | io_uring data path | ✅ | 🟡⚡ | ❌⚡ | ⬜ | ✅ | ❌ | ✅ | ✅ | ✅ | ❌ |
| s14 | sendfile() zero-copy upload | ✅ | ✅ | ❌⚡ | ⬜ | ✅* | ✅ | ✅ | ✅ | ✅ | ❌ |
| s15 | sendmmsg batched UDP | ✅ | ✅ | ✅ | ⬜ | ✅* | ✅ | ⬜ | ⬜ | ⬜ | ✅ |
| s16 | Loopback-only transfer | ✅ | ❌ | ❌ | ⬜ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ |
| s17 | In-container (docker) egress | ✅ | ✅ | ✅ | ⬜ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ |
| s18 | Low-and-slow drip upload | ✅ | ✅ | ✅ | ⬜ | ✅* | ✅ | ✅ | ✅ | ✅ | ✅ |
| s19 | Many small TCP connections | ✅ | ❌ | ❌ | ⬜ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| s20 | High-rate parallel burst | ✅ | ❌ | ❌ | ⬜ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| s21 | io_uring download (recv) | ✅ | ✅⚡ | 🟡⚡ | ⬜ | ✅ | ❌ | ✅ | ✅ | ❌ | ❌ |
| s22 | splice() zero-copy download | ✅ | ✅ | ✅⚡ | ⬜ | ✅* | ✅ | ✅ | ❌ | ✅ | ❌ |
| s23 | recvmmsg batched UDP (recv) | ✅ | ✅ | 🟡⚡ | ⬜ | ✅* | ✅ | ⬜ | ⬜ | ⬜ | ❌ |
| s24 | IPv6 UDP download | ✅ | ✅ | 🟡 | ⬜ | ✅* | ✅ | ⬜ | ⬜ | ⬜ | ✅ |

Legend: ✅ PASS · 🟡 PARTIAL · ❌ FAIL · ⬜ N/A · ⚠️ error · ⚡ flaky across trials · \* sniffnet OCR-flaky (scored best-of-5)

<!-- --8<-- [end:grid] -->
## Notes & partial/flaky explanations

- **picosnitch**
    - **s12 AF_PACKET raw-frame injection** — det=FAIL bw=FAIL. egress ratio≈0.0; AF_PACKET hands complete L2 frames to the driver, bypassing the inet socket path, so socket- and syscall-layer monitors record nothing; pcap taps see the frames but have no /proc/net/{tcp,udp} entry to attribute them to a process.
- **nethogs**
    - **s04 UDP bulk up+down** — det=PARTIAL bw=PASS. bucketed as unknown; egress ratio≈1.0
    - **s05 ICMP echo flood w/ payload** — det=FAIL bw=FAIL. not detected; egress ratio≈0.0; ICMP is neither TCP nor UDP; monitors that only parse TCP/UDP miss it entirely.
    - **s05** ⚡ inconsistent across trials (det ['FAIL', 'FAIL', 'FAIL', 'FAIL', 'PARTIAL'], bw ['FAIL', 'FAIL', 'FAIL', 'FAIL', 'FAIL']).
    - **s06 QUIC-style UDP:443 bulk** — det=PARTIAL bw=PASS. bucketed as unknown; egress ratio≈1.0
    - **s08 SCTP transfer** — det=FAIL bw=FAIL. not detected; ingress ratio≈0.0; SCTP is neither TCP nor UDP; TCP/UDP-only parsers miss it.
    - **s09 DNS-style small UDP:53 flood** — det=PARTIAL bw=PASS. bucketed as unknown; egress ratio≈1.0
    - **s10 Raw IP socket (proto 253) egress** — det=FAIL bw=FAIL. not detected; egress ratio≈0.0; raw sockets with a custom IP protocol carry no TCP/UDP header; TCP/UDP-only attribution misses them.
    - **s11 Short-lived processes** — det=PARTIAL bw=FAIL. bucketed as unknown; egress ratio≈0.3718; /proc-scan attribution loses processes that exit before the next scan; their traffic lands in an unknown bucket.
    - **s12 AF_PACKET raw-frame injection** — det=PARTIAL bw=PASS. bucketed as unknown; egress ratio≈0.9662; AF_PACKET hands complete L2 frames to the driver, bypassing the inet socket path, so socket- and syscall-layer monitors record nothing; pcap taps see the frames but have no /proc/net/{tcp,udp} entry to attribute them to a process.
    - **s13 io_uring data path** — det=PASS bw=PARTIAL. egress ratio≈0.8372
    - **s13** ⚡ inconsistent across trials (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL', 'FAIL']).
    - **s15 sendmmsg batched UDP** — det=PARTIAL bw=PASS. bucketed as unknown; egress ratio≈1.0
    - **s16 Loopback-only transfer** — det=PASS bw=FAIL. ingress ratio≈0.0; traffic never leaves lo, which many monitors skip by default (nethogs needs -a; sniffnet must capture the lo adapter).
    - **s17 In-container (docker) egress** — det=PARTIAL bw=PASS. bucketed as unknown; egress ratio≈1.0
    - **s19 Many small TCP connections** — det=PASS bw=FAIL. egress ratio≈0.3667
    - **s20 High-rate parallel burst** — det=PARTIAL bw=FAIL. bucketed as unknown; egress ratio≈0.236
    - **s21** ⚡ inconsistent across trials (det ['PASS', 'PASS', 'PASS', 'PARTIAL', 'PASS'], bw ['PARTIAL', 'PASS', 'PARTIAL', 'PASS', 'PASS']).
    - **s23 recvmmsg batched UDP (recv)** — det=PARTIAL bw=PASS. bucketed as unknown; ingress ratio≈1.0
    - **s24 IPv6 UDP download** — det=PARTIAL bw=PASS. bucketed as unknown; ingress ratio≈1.0
- **bandwhich**
    - **s01** ⚡ inconsistent across trials (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['PASS', 'PASS', 'PARTIAL', 'PASS', 'PASS']).
    - **s02 TCP bulk upload** — det=PASS bw=PARTIAL. egress ratio≈0.8512
    - **s02** ⚡ inconsistent across trials (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['PARTIAL', 'PASS', 'PARTIAL', 'PARTIAL', 'PARTIAL']).
    - **s03** ⚡ inconsistent across trials (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['PASS', 'PARTIAL', 'PASS', 'PASS', 'PASS']).
    - **s05 ICMP echo flood w/ payload** — det=FAIL bw=FAIL. not detected; egress ratio≈0.0; ICMP is neither TCP nor UDP; monitors that only parse TCP/UDP miss it entirely.
    - **s06 QUIC-style UDP:443 bulk** — det=PASS bw=PARTIAL. egress ratio≈0.8885
    - **s07 IPv6 TCP transfer** — det=PASS bw=PARTIAL. ingress ratio≈0.8312
    - **s07** ⚡ inconsistent across trials (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['PARTIAL', 'PARTIAL', 'PASS', 'PASS', 'PARTIAL']).
    - **s08 SCTP transfer** — det=FAIL bw=FAIL. not detected; ingress ratio≈0.0; SCTP is neither TCP nor UDP; TCP/UDP-only parsers miss it.
    - **s09 DNS-style small UDP:53 flood** — det=FAIL bw=FAIL. not detected; egress ratio≈0.0
    - **s10 Raw IP socket (proto 253) egress** — det=FAIL bw=FAIL. not detected; egress ratio≈0.0; raw sockets with a custom IP protocol carry no TCP/UDP header; TCP/UDP-only attribution misses them.
    - **s11 Short-lived processes** — det=PARTIAL bw=PARTIAL. bucketed as <UNKNOWN>; egress ratio≈0.8845; /proc-scan attribution loses processes that exit before the next scan; their traffic lands in an unknown bucket.
    - **s12 AF_PACKET raw-frame injection** — det=PARTIAL bw=PASS. bucketed as <UNKNOWN>; egress ratio≈0.7975; AF_PACKET hands complete L2 frames to the driver, bypassing the inet socket path, so socket- and syscall-layer monitors record nothing; pcap taps see the frames but have no /proc/net/{tcp,udp} entry to attribute them to a process.
    - **s12** ⚡ inconsistent across trials (det ['PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL'], bw ['PARTIAL', 'PARTIAL', 'PASS', 'PASS', 'PASS']).
    - **s13 io_uring data path** — det=PARTIAL bw=FAIL. bucketed as <UNKNOWN>; egress ratio≈0.5508
    - **s13** ⚡ inconsistent across trials (det ['PARTIAL', 'PASS', 'PARTIAL', 'PARTIAL', 'PARTIAL'], bw ['FAIL', 'FAIL', 'FAIL', 'PARTIAL', 'FAIL']).
    - **s14 sendfile() zero-copy upload** — det=PASS bw=FAIL. egress ratio≈0.7959
    - **s14** ⚡ inconsistent across trials (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['PARTIAL', 'FAIL', 'PASS', 'FAIL', 'PARTIAL']).
    - **s16 Loopback-only transfer** — det=PASS bw=FAIL. ingress ratio≈0.0; traffic never leaves lo, which many monitors skip by default (nethogs needs -a; sniffnet must capture the lo adapter).
    - **s17 In-container (docker) egress** — det=PARTIAL bw=PASS. bucketed as <UNKNOWN>; egress ratio≈0.9614
    - **s19 Many small TCP connections** — det=PASS bw=FAIL. egress ratio≈0.0162
    - **s20 High-rate parallel burst** — det=PARTIAL bw=FAIL. bucketed as <UNKNOWN>; egress ratio≈0.5433
    - **s21 io_uring download (recv)** — det=PARTIAL bw=PARTIAL. bucketed as <UNKNOWN>; ingress ratio≈0.7955
    - **s21** ⚡ inconsistent across trials (det ['PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL'], bw ['PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL', 'FAIL']).
    - **s22** ⚡ inconsistent across trials (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['PARTIAL', 'PASS', 'PASS', 'PASS', 'PARTIAL']).
    - **s23 recvmmsg batched UDP (recv)** — det=PASS bw=PARTIAL. ingress ratio≈0.7771
    - **s23** ⚡ inconsistent across trials (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['PARTIAL', 'PARTIAL', 'PARTIAL', 'PASS', 'PASS']).
    - **s24 IPv6 UDP download** — det=PASS bw=PARTIAL. ingress ratio≈0.8314
- **opensnitch**
    - **s04** ⚡ inconsistent across trials (det ['PASS', 'PASS', 'PASS', 'FAIL', 'PASS'], bw ['N/A', 'N/A', 'N/A', 'N/A', 'N/A']).
    - **s05 ICMP echo flood w/ payload** — det=FAIL bw=N/A. 0 connection record(s) matched process; ICMP is neither TCP nor UDP; monitors that only parse TCP/UDP miss it entirely.
    - **s06** ⚡ inconsistent across trials (det ['PASS', 'PASS', 'FAIL', 'PASS', 'PASS'], bw ['N/A', 'N/A', 'N/A', 'N/A', 'N/A']).
    - **s07** ⚡ inconsistent across trials (det ['FAIL', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['N/A', 'N/A', 'N/A', 'N/A', 'N/A']).
    - **s09** ⚡ inconsistent across trials (det ['PASS', 'PASS', 'PASS', 'PARTIAL', 'FAIL'], bw ['N/A', 'N/A', 'N/A', 'N/A', 'N/A']).
    - **s10 Raw IP socket (proto 253) egress** — det=FAIL bw=N/A. 0 connection record(s) matched process; raw sockets with a custom IP protocol carry no TCP/UDP header; TCP/UDP-only attribution misses them.
    - **s12 AF_PACKET raw-frame injection** — det=FAIL bw=N/A. 0 connection record(s) matched process; flow seen by dst only; AF_PACKET hands complete L2 frames to the driver, bypassing the inet socket path, so socket- and syscall-layer monitors record nothing; pcap taps see the frames but have no /proc/net/{tcp,udp} entry to attribute them to a process.
    - **s12** ⚡ inconsistent across trials (det ['PARTIAL', 'FAIL', 'FAIL', 'FAIL', 'FAIL'], bw ['N/A', 'N/A', 'N/A', 'N/A', 'N/A']).
    - **s15** ⚡ inconsistent across trials (det ['PASS', 'PASS', 'PASS', 'PASS', 'FAIL'], bw ['N/A', 'N/A', 'N/A', 'N/A', 'N/A']).
    - **s16 Loopback-only transfer** — det=FAIL bw=N/A. 0 connection record(s) matched process; traffic never leaves lo, which many monitors skip by default (nethogs needs -a; sniffnet must capture the lo adapter).
    - **s17 In-container (docker) egress** — det=FAIL bw=N/A. 0 connection record(s) matched process
- **sniffnet**
    - **s05 ICMP echo flood w/ payload** — det=PARTIAL bw=PASS. flow-level (pcap); process not read from GUI; egress ratio≈0.9674; ICMP is neither TCP nor UDP; monitors that only parse TCP/UDP miss it entirely.
    - **s06** * inconsistent across trials (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['FAIL', 'FAIL', 'FAIL', 'PASS', 'PASS']).
    - **s07** * inconsistent across trials (det ['PASS', 'PARTIAL', 'PASS', 'PASS', 'PASS'], bw ['FAIL', 'PASS', 'FAIL', 'PARTIAL', 'PARTIAL']).
    - **s08 SCTP transfer** — det=PASS bw=PARTIAL. per-process via GUI OCR (coarse, rounded); ingress ratio≈1.1048; SCTP is neither TCP nor UDP; TCP/UDP-only parsers miss it.
    - **s08** * inconsistent across trials (det ['PASS', 'PASS', 'PASS', 'PARTIAL', 'PARTIAL'], bw ['PARTIAL', 'PARTIAL', 'PARTIAL', 'FAIL', 'FAIL']).
    - **s09** * inconsistent across trials (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['PASS', 'FAIL', 'FAIL', 'FAIL', 'FAIL']).
    - **s10 Raw IP socket (proto 253) egress** — det=PARTIAL bw=FAIL. flow-level (pcap); process not read from GUI; egress ratio≈0.0; raw sockets with a custom IP protocol carry no TCP/UDP header; TCP/UDP-only attribution misses them.
    - **s11 Short-lived processes** — det=PARTIAL bw=PASS. flow-level (pcap); process not read from GUI; egress ratio≈0.9554; /proc-scan attribution loses processes that exit before the next scan; their traffic lands in an unknown bucket.
    - **s12 AF_PACKET raw-frame injection** — det=PARTIAL bw=PASS. flow-level (pcap); process not read from GUI; egress ratio≈0.9709; AF_PACKET hands complete L2 frames to the driver, bypassing the inet socket path, so socket- and syscall-layer monitors record nothing; pcap taps see the frames but have no /proc/net/{tcp,udp} entry to attribute them to a process.
    - **s13 io_uring data path** — det=PARTIAL bw=PASS. flow-level (pcap); process not read from GUI; egress ratio≈0.9561
    - **s14** * inconsistent across trials (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['PASS', 'FAIL', 'PASS', 'PASS', 'FAIL']).
    - **s15** * inconsistent across trials (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['FAIL', 'FAIL', 'PASS', 'FAIL', 'FAIL']).
    - **s16 Loopback-only transfer** — det=PARTIAL bw=FAIL. flow-level (pcap); process not read from GUI; ingress ratio≈0.0; traffic never leaves lo, which many monitors skip by default (nethogs needs -a; sniffnet must capture the lo adapter).
    - **s17 In-container (docker) egress** — det=PARTIAL bw=FAIL. flow-level (pcap); process not read from GUI; egress ratio≈2.8671
    - **s18** * inconsistent across trials (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['FAIL', 'FAIL', 'PASS', 'FAIL', 'FAIL']).
    - **s19 Many small TCP connections** — det=PARTIAL bw=PASS. flow-level (pcap); process not read from GUI; egress ratio≈0.9511
    - **s20 High-rate parallel burst** — det=PARTIAL bw=PASS. flow-level (pcap); process not read from GUI; egress ratio≈0.9549
    - **s21 io_uring download (recv)** — det=PARTIAL bw=PASS. flow-level (pcap); process not read from GUI; ingress ratio≈0.9712
    - **s22** * inconsistent across trials (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['FAIL', 'FAIL', 'PASS', 'FAIL', 'FAIL']).
    - **s23** * inconsistent across trials (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['FAIL', 'FAIL', 'PASS', 'PASS', 'PASS']).
    - **s24** * inconsistent across trials (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['FAIL', 'PASS', 'FAIL', 'PASS', 'PASS']).
- **little-snitch**
    - **s05 ICMP echo flood w/ payload** — det=FAIL bw=FAIL. web-socket per-app stats; egress ratio≈0.4611; ICMP is neither TCP nor UDP; monitors that only parse TCP/UDP miss it entirely.
    - **s05** ⚡ inconsistent across trials (det ['PASS', 'FAIL', 'FAIL', 'FAIL', 'FAIL'], bw ['FAIL', 'FAIL', 'FAIL', 'FAIL', 'FAIL']).
    - **s09 DNS-style small UDP:53 flood** — det=PASS bw=FAIL. web-socket per-app stats; egress ratio≈0.4521
    - **s10 Raw IP socket (proto 253) egress** — det=FAIL bw=FAIL. no app row (attributed to a parent app); egress ratio≈0.0; raw sockets with a custom IP protocol carry no TCP/UDP header; TCP/UDP-only attribution misses them.
    - **s12 AF_PACKET raw-frame injection** — det=FAIL bw=FAIL. no app row (attributed to a parent app); egress ratio≈0.0; AF_PACKET hands complete L2 frames to the driver, bypassing the inet socket path, so socket- and syscall-layer monitors record nothing; pcap taps see the frames but have no /proc/net/{tcp,udp} entry to attribute them to a process.
    - **s13 io_uring data path** — det=PASS bw=FAIL. web-socket per-app stats; egress ratio≈0.4038
    - **s16 Loopback-only transfer** — det=FAIL bw=FAIL. no app row (attributed to a parent app); ingress ratio≈0.0; traffic never leaves lo, which many monitors skip by default (nethogs needs -a; sniffnet must capture the lo adapter).
    - **s17 In-container (docker) egress** — det=FAIL bw=FAIL. no app row (attributed to a parent app); egress ratio≈0.0
    - **s21 io_uring download (recv)** — det=PASS bw=FAIL. web-socket per-app stats; ingress ratio≈0.366
- **bcc**
    - **s03 TCP full-duplex up+down** — det=PARTIAL bw=PASS. tcplife fires on session close; egress ratio≈1.0
    - **s03** ⚡ inconsistent across trials (det ['PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL'], bw ['PASS', 'PASS', 'PASS', 'PASS', 'FAIL']).
    - **s21 io_uring download (recv)** — det=PARTIAL bw=PASS. tcplife fires on session close; ingress ratio≈1.0
    - **s22 splice() zero-copy download** — det=PARTIAL bw=PASS. tcplife fires on session close; ingress ratio≈1.0
- **bcc tcptop**
    - **s22 splice() zero-copy download** — det=PASS bw=FAIL. tcptop per-interval KB summed over the trial; ingress ratio≈0.0
- **bpftrace**
    - **s21 io_uring download (recv)** — det=PASS bw=FAIL. bpftrace tcp_sendmsg/tcp_cleanup_rbuf, summed per second; ingress ratio≈77142.3331
- **sysdig**
    - **s12 AF_PACKET raw-frame injection** — det=FAIL bw=FAIL. AF_PACKET bypasses sysdig's network syscall accounting; egress ratio≈0.0; AF_PACKET hands complete L2 frames to the driver, bypassing the inet socket path, so socket- and syscall-layer monitors record nothing; pcap taps see the frames but have no /proc/net/{tcp,udp} entry to attribute them to a process.
    - **s13 io_uring data path** — det=PASS bw=FAIL. sysdig network I/O syscall bytes, per process; egress ratio≈0.0
    - **s14 sendfile() zero-copy upload** — det=PASS bw=FAIL. sysdig network I/O syscall bytes, per process; egress ratio≈0.0
    - **s21 io_uring download (recv)** — det=PASS bw=FAIL. sysdig network I/O syscall bytes, per process; ingress ratio≈0.0
    - **s22 splice() zero-copy download** — det=PASS bw=FAIL. sysdig network I/O syscall bytes, per process; ingress ratio≈0.0
    - **s23 recvmmsg batched UDP (recv)** — det=PASS bw=FAIL. sysdig network I/O syscall bytes, per process; ingress ratio≈1.9879
