# Bandwidth scorecard: are the bytes measured accurately (±10% PASS, ±25% PARTIAL)?

<!-- --8<-- [start:grid] -->
## Bandwidth accuracy

Scored on bytes reported, independently of attribution: a tool that measured the traffic but bucketed it as unknown is scored here on those bytes, and the detection grid records that miss as PARTIAL.

| # | Scenario | picosnitch | NetHogs | bandwhich | OpenSnitch | Sniffnet | Little Snitch | BCC tcplife/tcpconnect | BCC tcptop | bpftrace script | Sysdig |
|---|---|---|---|---|---|---|---|---|---|---|---|
| s01 | TCP bulk download (control) | ✅ | ✅ | ✅* | ⬜ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| s02 | TCP bulk upload | ✅ | ✅ | 🟡* | ⬜ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| s03 | TCP full-duplex up+down | ✅ | ✅ | ✅* | ⬜ | ⬜ | ✅ | ✅ | ✅ | ✅ | ✅ |
| s04 | UDP bulk up+down | ✅ | ✅ | ✅ | ⬜ | ⬜ | ✅ | ⬜ | ⬜ | ⬜ | ✅ |
| s05 | ICMP echo flood w/ payload | ✅ | ❌ | ❌ | ⬜ | ❌ | ❌ | ⬜ | ⬜ | ⬜ | ✅ |
| s06 | UDP/443 bulk | ✅ | ✅ | 🟡 | ⬜ | ✅ | ✅ | ⬜ | ⬜ | ⬜ | ✅ |
| s07 | IPv6 TCP transfer | ✅ | ✅ | 🟡* | ⬜ | 🟡 | ✅ | ✅ | ✅ | ✅ | ✅ |
| s08 | SCTP transfer | ✅ | ❌ | ❌ | ⬜ | ❌ | ✅ | ⬜ | ⬜ | ⬜ | ✅ |
| s09 | Small-packet UDP/53 flood | ✅ | ✅ | ❌ | ⬜ | ✅ | ❌ | ⬜ | ⬜ | ⬜ | ✅ |
| s10 | Raw IP socket (proto 253) egress | ✅ | ❌ | ❌ | ⬜ | ❌ | ❌ | ⬜ | ⬜ | ⬜ | ✅ |
| s11 | Short-lived processes | ✅ | ❌ | 🟡 | ⬜ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| s12 | AF_PACKET raw-frame injection | ❌ | ✅ | ✅* | ⬜ | ✅ | ❌ | ⬜ | ⬜ | ⬜ | ✅ |
| s13 | io_uring data path | ✅ | 🟡 | ❌ | ⬜ | ✅ | ❌ | ✅ | ✅ | ✅ | ❌ |
| s14 | sendfile() zero-copy upload | ✅ | ✅ | ❌ | ⬜ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| s15 | sendmmsg batched UDP | ✅ | ✅ | 🟡 | ⬜ | ✅ | ✅ | ⬜ | ⬜ | ⬜ | ✅ |
| s16 | Loopback-only transfer | ✅ | ❌ | ❌ | ⬜ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ |
| s17 | In-container (docker) egress | ✅ | ✅ | ✅ | ⬜ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ |
| s18 | Low-and-slow drip upload | ✅ | ✅ | ✅ | ⬜ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| s19 | Many small TCP connections | ✅ | ❌ | ❌ | ⬜ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| s20 | High-rate parallel burst | ✅ | ❌ | ❌ | ⬜ | ✅* | ✅ | ✅ | ✅ | ✅ | ✅ |
| s21 | io_uring download (recv) | ✅ | 🟡* | ❌* | ⬜ | 🟡 | ❌* | ✅ | ✅ | ❌ | ❌ |
| s22 | splice() zero-copy download | ✅ | ✅ | ✅* | ⬜ | ✅ | ✅ | ✅ | ❌ | ✅ | ❌ |
| s23 | recvmmsg batched UDP (recv) | ✅ | ✅ | 🟡* | ⬜ | ✅ | ✅ | ⬜ | ⬜ | ⬜ | ❌ |
| s24 | IPv6 UDP download | ✅ | ✅ | 🟡* | ⬜ | ✅ | ✅ | ⬜ | ⬜ | ⬜ | ✅ |

Legend: ✅ PASS · 🟡 PARTIAL · ❌ FAIL · ⬜ N/A · ⚠️ error · \* trials disagreed, see the note

<!-- --8<-- [end:grid] -->
## Result notes

- **picosnitch**
    - **s12 AF_PACKET raw-frame injection**: det=FAIL bw=FAIL. recorded: nothing x5. egress ratio≈0.0.
- **NetHogs**
    - **s04 UDP bulk up+down**: det=PARTIAL bw=PASS. recorded: nothing x5. bucketed as unknown; egress ratio≈1.0.
    - **s05 ICMP echo flood w/ payload**: det=FAIL bw=FAIL. recorded: nothing x5. not detected; egress ratio≈0.0.
    - **s06 UDP/443 bulk**: det=PARTIAL bw=PASS. recorded: nothing x5. bucketed as unknown; egress ratio≈1.0.
    - **s08 SCTP transfer**: det=FAIL bw=FAIL. recorded: nothing x5. not detected; ingress ratio≈0.0.
    - **s09 Small-packet UDP/53 flood**: det=PARTIAL bw=PASS. recorded: nothing x5. bucketed as unknown; egress ratio≈1.0.
    - **s10 Raw IP socket (proto 253) egress**: det=FAIL bw=FAIL. recorded: nothing x5. not detected; egress ratio≈0.0.
    - **s11 Short-lived processes**: det=PARTIAL bw=FAIL. recorded: nothing x5. bucketed as unknown; egress ratio≈0.421.
    - **s12 AF_PACKET raw-frame injection**: det=PARTIAL bw=PASS. recorded: nothing x5. bucketed as unknown; egress ratio≈0.9271.
    - **s13 io_uring data path**: det=PASS bw=PARTIAL. recorded: bg_uring x5. egress ratio≈0.8285.
    - **s15 sendmmsg batched UDP**: det=PARTIAL bw=PASS. recorded: nothing x5. bucketed as unknown; egress ratio≈1.0.
    - **s16 Loopback-only transfer**: det=PASS bw=FAIL. recorded: bg_loop x5. ingress ratio≈0.0.
    - **s17 In-container (docker) egress**: det=PARTIAL bw=PASS. recorded: nothing x5. bucketed as unknown; egress ratio≈1.0.
    - **s19 Many small TCP connections**: det=PASS bw=FAIL. recorded: bg_many x5. egress ratio≈0.3667.
    - **s20 High-rate parallel burst**: det=PARTIAL bw=FAIL. recorded: nothing x5. bucketed as unknown; egress ratio≈0.2336.
    - **s21 io_uring download (recv)**: det=PASS bw=PARTIAL. recorded: bg_uringdl x5 (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['PARTIAL', 'PARTIAL', 'PASS', 'PASS', 'PARTIAL']).
    - **s23 recvmmsg batched UDP (recv)**: det=PARTIAL bw=PASS. recorded: nothing x5. bucketed as unknown; ingress ratio≈1.0.
    - **s24 IPv6 UDP download**: det=PARTIAL bw=PASS. recorded: nothing x5. bucketed as unknown; ingress ratio≈1.0.
- **bandwhich**
    - **s01 TCP bulk download (control)**: det=PASS bw=PASS. recorded: bg_tcp_dl x5 (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['PASS', 'PARTIAL', 'PASS', 'PASS', 'PARTIAL']).
    - **s02 TCP bulk upload**: det=PASS bw=PARTIAL. recorded: bg_tcp_ul x5 (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['PASS', 'PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL']).
    - **s03 TCP full-duplex up+down**: det=PASS bw=PASS. recorded: bg_tcp_duo x5 (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['PARTIAL', 'PASS', 'PASS', 'PASS', 'PASS']).
    - **s05 ICMP echo flood w/ payload**: det=FAIL bw=FAIL. recorded: nothing x5. not detected; egress ratio≈0.0.
    - **s06 UDP/443 bulk**: det=PASS bw=PARTIAL. recorded: bg_quic x5. egress ratio≈0.8198.
    - **s07 IPv6 TCP transfer**: det=PASS bw=PARTIAL. recorded: bg_tcp6 x5 (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['PASS', 'PASS', 'PARTIAL', 'PARTIAL', 'PARTIAL']).
    - **s08 SCTP transfer**: det=FAIL bw=FAIL. recorded: nothing x5. not detected; ingress ratio≈0.0.
    - **s09 Small-packet UDP/53 flood**: det=FAIL bw=FAIL. recorded: nothing x5. not detected; egress ratio≈0.0.
    - **s10 Raw IP socket (proto 253) egress**: det=FAIL bw=FAIL. recorded: nothing x5. not detected; egress ratio≈0.0.
    - **s11 Short-lived processes**: det=PARTIAL bw=PARTIAL. recorded: nothing x5. bucketed as <UNKNOWN>; egress ratio≈0.8278.
    - **s12 AF_PACKET raw-frame injection**: det=PARTIAL bw=PASS. recorded: nothing x5 (det ['PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL'], bw ['PARTIAL', 'PASS', 'PASS', 'PASS', 'PARTIAL']). bucketed as <UNKNOWN>.
    - **s13 io_uring data path**: det=PARTIAL bw=FAIL. recorded: nothing x3, bg_uring x2 (det ['PASS', 'PARTIAL', 'PARTIAL', 'PARTIAL', 'PASS'], bw ['FAIL', 'FAIL', 'FAIL', 'FAIL', 'FAIL']).
    - **s14 sendfile() zero-copy upload**: det=PASS bw=FAIL. recorded: bg_sendf x5. egress ratio≈0.7333.
    - **s15 sendmmsg batched UDP**: det=PASS bw=PARTIAL. recorded: bg_smmsg x5. egress ratio≈0.8583.
    - **s16 Loopback-only transfer**: det=PASS bw=FAIL. recorded: bg_loop x5. ingress ratio≈0.0.
    - **s17 In-container (docker) egress**: det=PARTIAL bw=PASS. recorded: nothing x5. bucketed as <UNKNOWN>; egress ratio≈0.9584.
    - **s19 Many small TCP connections**: det=PASS bw=FAIL. recorded: bg_many x5. egress ratio≈0.0162.
    - **s20 High-rate parallel burst**: det=PARTIAL bw=FAIL. recorded: nothing x5. bucketed as <UNKNOWN>; egress ratio≈0.5393.
    - **s21 io_uring download (recv)**: det=PARTIAL bw=FAIL. recorded: nothing x5 (det ['PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL'], bw ['FAIL', 'FAIL', 'FAIL', 'PARTIAL', 'FAIL']). bucketed as <UNKNOWN>.
    - **s22 splice() zero-copy download**: det=PASS bw=PASS. recorded: bg_splice x5 (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['PASS', 'PARTIAL', 'PASS', 'PASS', 'PASS']).
    - **s23 recvmmsg batched UDP (recv)**: det=PASS bw=PARTIAL. recorded: bg_rmmsg x5 (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['PARTIAL', 'PASS', 'PARTIAL', 'PARTIAL', 'PARTIAL']).
    - **s24 IPv6 UDP download**: det=PASS bw=PARTIAL. recorded: bg_udp6 x5 (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['PASS', 'PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL']).
- **OpenSnitch**
    - **s04 UDP bulk up+down**: det=PASS bw=N/A. recorded: bg_udp x4, nothing x1 (det ['PASS', 'PASS', 'FAIL', 'PASS', 'PASS'], bw ['N/A', 'N/A', 'N/A', 'N/A', 'N/A']). 17978 connection record(s) matched process.
    - **s05 ICMP echo flood w/ payload**: det=FAIL bw=N/A. recorded: nothing x5. 0 connection record(s) matched process.
    - **s06 UDP/443 bulk**: det=PASS bw=N/A. recorded: bg_quic x4, nothing x1 (det ['PASS', 'PASS', 'FAIL', 'PASS', 'PASS'], bw ['N/A', 'N/A', 'N/A', 'N/A', 'N/A']). 17953 connection record(s) matched process.
    - **s07 IPv6 TCP transfer**: det=PASS bw=N/A. recorded: bg_tcp6 x4, nothing x1 (det ['FAIL', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['N/A', 'N/A', 'N/A', 'N/A', 'N/A']). 0 connection record(s) matched process.
    - **s09 Small-packet UDP/53 flood**: det=PASS bw=N/A. recorded: bg_dns x4, nothing x1 (det ['PASS', 'PASS', 'PASS', 'PASS', 'FAIL'], bw ['N/A', 'N/A', 'N/A', 'N/A', 'N/A']). 15676 connection record(s) matched process.
    - **s10 Raw IP socket (proto 253) egress**: det=FAIL bw=N/A. recorded: nothing x5. 0 connection record(s) matched process.
    - **s12 AF_PACKET raw-frame injection**: det=FAIL bw=N/A. recorded: nothing x5. 0 connection record(s) matched process.
    - **s15 sendmmsg batched UDP**: det=PASS bw=N/A. recorded: bg_smmsg x4, nothing x1 (det ['PASS', 'PASS', 'PASS', 'FAIL', 'PASS'], bw ['N/A', 'N/A', 'N/A', 'N/A', 'N/A']). 17973 connection record(s) matched process.
    - **s16 Loopback-only transfer**: det=FAIL bw=N/A. recorded: nothing x5. 0 connection record(s) matched process.
    - **s17 In-container (docker) egress**: det=FAIL bw=N/A. recorded: nothing x5. 0 connection record(s) matched process.
- **Sniffnet**
    - **s05 ICMP echo flood w/ payload**: det=FAIL bw=FAIL. recorded: nothing x5. no Program row; egress ratio≈0.0.
    - **s07 IPv6 TCP transfer**: det=PASS bw=PARTIAL. recorded: bg_tcp6 x5. per-program total from the GUI; ingress ratio≈1.122.
    - **s08 SCTP transfer**: det=FAIL bw=FAIL. recorded: nothing x5. no Program row; ingress ratio≈0.0.
    - **s10 Raw IP socket (proto 253) egress**: det=FAIL bw=FAIL. recorded: nothing x5. no Program row; egress ratio≈0.0.
    - **s11 Short-lived processes**: det=PARTIAL bw=PASS. recorded: ? x5. listed unattributed (?) by Sniffnet; egress ratio≈1.051.
    - **s12 AF_PACKET raw-frame injection**: det=PARTIAL bw=PASS. recorded: ? x5. listed unattributed (?) by Sniffnet; egress ratio≈1.0437.
    - **s13 io_uring data path**: det=PARTIAL bw=PASS. recorded: ? x5. listed unattributed (?) by Sniffnet; egress ratio≈1.0353.
    - **s16 Loopback-only transfer**: det=FAIL bw=FAIL. recorded: nothing x5. no Program row; ingress ratio≈0.0.
    - **s17 In-container (docker) egress**: det=PARTIAL bw=PASS. recorded: ? x5. listed unattributed (?) by Sniffnet; egress ratio≈1.0354.
    - **s19 Many small TCP connections**: det=PARTIAL bw=PASS. recorded: ? x5. listed unattributed (?) by Sniffnet; egress ratio≈1.0648.
    - **s20 High-rate parallel burst**: det=PARTIAL bw=PASS. recorded: ? x5 (det ['PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL'], bw ['PASS', 'PARTIAL', 'PASS', 'PASS', 'PASS']). listed unattributed (?) by Sniffnet.
    - **s21 io_uring download (recv)**: det=PARTIAL bw=PARTIAL. recorded: ? x5. listed unattributed (?) by Sniffnet; ingress ratio≈1.1228.
- **Little Snitch**
    - **s05 ICMP echo flood w/ payload**: det=FAIL bw=FAIL. recorded: nothing x4, bg_icmp x1 (det ['PASS', 'FAIL', 'FAIL', 'FAIL', 'FAIL'], bw ['FAIL', 'FAIL', 'FAIL', 'FAIL', 'FAIL']). WebSocket per-app stats.
    - **s09 Small-packet UDP/53 flood**: det=PASS bw=FAIL. recorded: bg_dns x5. WebSocket per-app stats; egress ratio≈0.4829.
    - **s10 Raw IP socket (proto 253) egress**: det=FAIL bw=FAIL. recorded: nothing x5. no matching app row; egress ratio≈0.0.
    - **s12 AF_PACKET raw-frame injection**: det=FAIL bw=FAIL. recorded: nothing x5. no matching app row; egress ratio≈0.0.
    - **s13 io_uring data path**: det=PASS bw=FAIL. recorded: bg_uring x5. WebSocket per-app stats; egress ratio≈0.4373.
    - **s16 Loopback-only transfer**: det=FAIL bw=FAIL. recorded: nothing x5. no matching app row; ingress ratio≈0.0.
    - **s17 In-container (docker) egress**: det=FAIL bw=FAIL. recorded: nothing x5. no matching app row; egress ratio≈0.0.
    - **s21 io_uring download (recv)**: det=PASS bw=FAIL. recorded: bg_uringdl x5 (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['FAIL', 'FAIL', 'PARTIAL', 'FAIL', 'FAIL']). WebSocket per-app stats.
- **BCC tcplife/tcpconnect**
    - **s03 TCP full-duplex up+down**: det=PARTIAL bw=PASS. recorded: nothing x5. tcplife fires on session close; egress ratio≈1.0.
    - **s21 io_uring download (recv)**: det=PARTIAL bw=PASS. recorded: nothing x5. tcplife fires on session close; ingress ratio≈1.0.
    - **s22 splice() zero-copy download**: det=PARTIAL bw=PASS. recorded: nothing x5. tcplife fires on session close; ingress ratio≈1.0.
    - _run note:_ control passed on the second attempt (first attempt missed; probe warm-up)
- **BCC tcptop**
    - **s22 splice() zero-copy download**: det=PASS bw=FAIL. recorded: bg_splice x5. tcptop per-interval KB summed over the trial; ingress ratio≈0.0.
- **bpftrace script**
    - **s21 io_uring download (recv)**: det=PASS bw=FAIL. recorded: bg_uringdl x5. bpftrace tcp_sendmsg/tcp_cleanup_rbuf, summed per second; ingress ratio≈74070.3331.
- **Sysdig**
    - **s13 io_uring data path**: det=PASS bw=FAIL. recorded: bg_uring x5. Sysdig network I/O syscall bytes, per process; egress ratio≈0.0.
    - **s14 sendfile() zero-copy upload**: det=PASS bw=FAIL. recorded: bg_sendf x5. Sysdig network I/O syscall bytes, per process; egress ratio≈0.0.
    - **s21 io_uring download (recv)**: det=PASS bw=FAIL. recorded: bg_uringdl x5. Sysdig network I/O syscall bytes, per process; ingress ratio≈0.0.
    - **s22 splice() zero-copy download**: det=PASS bw=FAIL. recorded: bg_splice x5. Sysdig network I/O syscall bytes, per process; ingress ratio≈0.0.
    - **s23 recvmmsg batched UDP (recv)**: det=PASS bw=FAIL. recorded: bg_rmmsg x5. Sysdig network I/O syscall bytes, per process; ingress ratio≈1.9545.
