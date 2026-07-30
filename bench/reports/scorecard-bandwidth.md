# Bandwidth scorecard: are the bytes measured accurately (±10% PASS, ±25% PARTIAL)?

<!-- --8<-- [start:grid] -->
## Bandwidth accuracy

Scored on bytes reported, independently of attribution: a tool that measured the traffic but bucketed it as unknown is scored here on those bytes, and the detection grid records that miss as PARTIAL.

| # | Scenario | picosnitch | NetHogs | bandwhich | OpenSnitch | Sniffnet | Little Snitch | BCC tcplife/tcpconnect | BCC tcptop | bpftrace script | Sysdig |
|---|---|---|---|---|---|---|---|---|---|---|---|
| s01 | TCP bulk download (control) | ✅ | ✅ | ✅* | ⬜ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| s02 | TCP bulk upload | ✅ | ✅ | 🟡* | ⬜ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| s03 | TCP full-duplex up+down | ✅ | ✅ | ✅* | ⬜ | ⬜ | ✅ | ✅ | ✅ | ✅ | ✅ |
| s04 | UDP bulk up+down | ✅ | ✅ | 🟡 | ⬜ | ⬜ | ✅ | ⬜ | ⬜ | ⬜ | ✅ |
| s05 | ICMP echo flood w/ payload | ✅ | ❌ | ❌ | ⬜ | ❌ | ❌ | ⬜ | ⬜ | ⬜ | ✅ |
| s06 | UDP/443 bulk | ✅ | ✅ | ✅* | ⬜ | ✅ | ✅ | ⬜ | ⬜ | ⬜ | ✅ |
| s07 | IPv6 TCP transfer | ✅ | ✅ | ✅* | ⬜ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| s08 | SCTP transfer | ✅ | ❌ | ❌ | ⬜ | ❌ | ✅ | ⬜ | ⬜ | ⬜ | ✅ |
| s09 | Small-packet UDP/53 flood | ✅ | ✅ | ❌* | ⬜ | ✅ | ❌ | ⬜ | ⬜ | ⬜ | ✅ |
| s10 | Raw IP socket (proto 253) egress | ✅ | ❌ | ❌ | ⬜ | ❌ | ❌ | ⬜ | ⬜ | ⬜ | ✅ |
| s11 | Short-lived processes | ✅ | ❌ | 🟡* | ⬜ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| s12 | AF_PACKET raw-frame injection | ❌ | ✅* | ✅* | ⬜ | ✅ | ❌ | ⬜ | ⬜ | ⬜ | ✅ |
| s13 | io_uring data path | ✅ | 🟡* | ❌* | ⬜ | ✅ | ❌ | ✅ | ✅ | ✅ | ❌ |
| s14 | sendfile() zero-copy upload | ✅ | ✅ | 🟡* | ⬜ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| s15 | sendmmsg batched UDP | ✅ | ✅ | ✅* | ⬜ | ✅ | ✅ | ⬜ | ⬜ | ⬜ | ✅ |
| s16 | Loopback-only transfer | ✅ | ⬜ | ⬜ | ⬜ | ⬜ | ❌ | ✅ | ✅ | ✅ | ✅ |
| s17 | In-container (docker) egress | ✅ | ✅ | ✅ | ⬜ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ |
| s18 | Low-and-slow drip upload | ✅ | ✅ | ✅ | ⬜ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| s19 | Many small TCP connections | ✅ | ❌ | ❌ | ⬜ | ✅ | ✅* | ✅ | ✅ | ✅ | ✅ |
| s20 | High-rate parallel burst | ✅ | ❌ | ❌ | ⬜ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| s21 | io_uring download (recv) | ✅ | ✅ | ❌ | ⬜ | ✅ | ❌ | ✅ | ✅ | ✅ | ❌ |
| s22 | splice() zero-copy download | ✅ | ✅ | 🟡* | ⬜ | ✅ | ✅ | ✅ | ❌ | ✅ | ❌ |
| s23 | recvmmsg batched UDP (recv) | ✅ | ✅ | ✅* | ⬜ | ✅ | ✅ | ⬜ | ⬜ | ⬜ | ❌ |
| s24 | IPv6 UDP download | ✅ | ✅ | 🟡* | ⬜ | ✅ | ✅ | ⬜ | ⬜ | ⬜ | ✅ |

Legend: ✅ PASS · 🟡 PARTIAL · ❌ FAIL · ⬜ N/A · ⚠️ error · \* trials disagreed, see the note

<!-- --8<-- [end:grid] -->
## Result notes

- **picosnitch**
    - **s12 AF_PACKET raw-frame injection**: det=FAIL bw=FAIL. recorded: nothing x5. egress ratio≈0.0.
- **NetHogs**
    - **s04 UDP bulk up+down**: det=PARTIAL bw=PASS. recorded: unknown x5. named 0/0, unknown 25921512/25920768; egress ratio≈1.0.
    - **s05 ICMP echo flood w/ payload**: det=FAIL bw=FAIL. recorded: nothing x5. egress ratio≈0.0.
    - **s06 UDP/443 bulk**: det=PARTIAL bw=PASS. recorded: unknown x5. named 0/0, unknown 25921000/0; egress ratio≈1.0.
    - **s08 SCTP transfer**: det=FAIL bw=FAIL. recorded: nothing x5. ingress ratio≈0.0.
    - **s09 Small-packet UDP/53 flood**: det=PARTIAL bw=PASS. recorded: unknown x5. named 0/0, unknown 6947000/0; egress ratio≈1.0.
    - **s10 Raw IP socket (proto 253) egress**: det=FAIL bw=FAIL. recorded: nothing x5. egress ratio≈0.0.
    - **s11 Short-lived processes**: det=PARTIAL bw=FAIL. recorded: unknown x5. named 0/0, unknown 4517140/32008; egress ratio≈0.4116.
    - **s12 AF_PACKET raw-frame injection**: det=PARTIAL bw=PASS. recorded: unknown x5 (det ['PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL'], bw ['FAIL', 'PASS', 'PASS', 'PASS', 'PASS']).
    - **s13 io_uring data path**: det=PASS bw=PARTIAL. recorded: bg_uring x5 (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['PARTIAL', 'PARTIAL', 'FAIL', 'FAIL', 'PARTIAL']).
    - **s15 sendmmsg batched UDP**: det=PARTIAL bw=PASS. recorded: unknown x5. named 0/0, unknown 25933000/0; egress ratio≈1.0.
    - **s17 In-container (docker) egress**: det=PARTIAL bw=PASS. recorded: unknown x5. named 0/0, unknown 26332000/36704; egress ratio≈1.0.
    - **s19 Many small TCP connections**: det=PASS bw=FAIL. recorded: bg_many x5. named 1516550/34892, unknown 2550000/58310; egress ratio≈0.3667.
    - **s20 High-rate parallel burst**: det=PARTIAL bw=FAIL. recorded: unknown x5. named 0/0, unknown 1944000/14526; egress ratio≈0.2354.
    - **s23 recvmmsg batched UDP (recv)**: det=PARTIAL bw=PASS. recorded: unknown x5. named 0/0, unknown 0/25921000; ingress ratio≈1.0.
    - **s24 IPv6 UDP download**: det=PARTIAL bw=PASS. recorded: unknown x5. named 0/0, unknown 0/26281000; ingress ratio≈1.0.
- **bandwhich**
    - **s01 TCP bulk download (control)**: det=PASS bw=PASS. recorded: bg_tcp_dl x5 (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['PASS', 'PARTIAL', 'PASS', 'PASS', 'PARTIAL']).
    - **s02 TCP bulk upload**: det=PASS bw=PARTIAL. recorded: bg_tcp_ul x5 (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['PARTIAL', 'PASS', 'PARTIAL', 'PASS', 'PARTIAL']).
    - **s03 TCP full-duplex up+down**: det=PASS bw=PASS. recorded: bg_tcp_duo x5 (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['PARTIAL', 'PASS', 'PASS', 'PASS', 'PASS']).
    - **s04 UDP bulk up+down**: det=PASS bw=PARTIAL. recorded: bg_udp x5. named 21500218/21494525, <UNKNOWN> 3810045/3815100; egress ratio≈0.8495.
    - **s05 ICMP echo flood w/ payload**: det=FAIL bw=FAIL. recorded: nothing x5. egress ratio≈0.0.
    - **s06 UDP/443 bulk**: det=PASS bw=PASS. recorded: bg_quic x5 (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['PASS', 'PARTIAL', 'PASS', 'PARTIAL', 'PASS']).
    - **s07 IPv6 TCP transfer**: det=PASS bw=PASS. recorded: bg_tcp6 x5 (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['PASS', 'PASS', 'PASS', 'PASS', 'PARTIAL']).
    - **s08 SCTP transfer**: det=FAIL bw=FAIL. recorded: nothing x5. ingress ratio≈0.0.
    - **s09 Small-packet UDP/53 flood**: det=PASS bw=FAIL. recorded: bg_dns x5 (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['FAIL', 'PARTIAL', 'PASS', 'FAIL', 'FAIL']).
    - **s10 Raw IP socket (proto 253) egress**: det=FAIL bw=FAIL. recorded: nothing x5. egress ratio≈0.0.
    - **s11 Short-lived processes**: det=PARTIAL bw=PARTIAL. recorded: <UNKNOWN> x5 (det ['PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL'], bw ['PARTIAL', 'PARTIAL', 'PARTIAL', 'PASS', 'PARTIAL']).
    - **s12 AF_PACKET raw-frame injection**: det=PARTIAL bw=PASS. recorded: <UNKNOWN> x5 (det ['PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL'], bw ['FAIL', 'PASS', 'PASS', 'PASS', 'PARTIAL']).
    - **s13 io_uring data path**: det=PARTIAL bw=FAIL. recorded: <UNKNOWN> x5 (det ['PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL'], bw ['PARTIAL', 'FAIL', 'FAIL', 'FAIL', 'FAIL']).
    - **s14 sendfile() zero-copy upload**: det=PASS bw=PARTIAL. recorded: bg_sendf x5 (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['PARTIAL', 'PARTIAL', 'PARTIAL', 'FAIL', 'FAIL']).
    - **s15 sendmmsg batched UDP**: det=PASS bw=PASS. recorded: bg_smmsg x5 (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['PASS', 'PARTIAL', 'PASS', 'PARTIAL', 'PASS']).
    - **s17 In-container (docker) egress**: det=PARTIAL bw=PASS. recorded: <UNKNOWN> x5. named 0/0, <UNKNOWN> 24980758/43455; egress ratio≈0.9708.
    - **s19 Many small TCP connections**: det=PASS bw=FAIL. recorded: bg_many x5. named 67165/710, <UNKNOWN> 3978244/45257; egress ratio≈0.0167.
    - **s20 High-rate parallel burst**: det=PARTIAL bw=FAIL. recorded: <UNKNOWN> x5. named 0/0, <UNKNOWN> 4620200/28640; egress ratio≈0.5727.
    - **s21 io_uring download (recv)**: det=PARTIAL bw=FAIL. recorded: <UNKNOWN> x4, bg_uringdl x1 (det ['PARTIAL', 'PARTIAL', 'PASS', 'PARTIAL', 'PARTIAL'], bw ['FAIL', 'FAIL', 'FAIL', 'FAIL', 'FAIL']).
    - **s22 splice() zero-copy download**: det=PASS bw=PARTIAL. recorded: bg_splice x5 (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['PARTIAL', 'PARTIAL', 'PASS', 'PARTIAL', 'PASS']).
    - **s23 recvmmsg batched UDP (recv)**: det=PASS bw=PASS. recorded: bg_rmmsg x5 (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['PASS', 'PASS', 'PASS', 'PASS', 'PARTIAL']).
    - **s24 IPv6 UDP download**: det=PASS bw=PARTIAL. recorded: bg_udp6 x5 (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['PARTIAL', 'PARTIAL', 'PASS', 'PARTIAL', 'PARTIAL']).
- **OpenSnitch**
    - **s04 UDP bulk up+down**: det=PASS bw=N/A. recorded: bg_udp x4, nothing x1 (det ['PASS', 'PASS', 'FAIL', 'PASS', 'PASS'], bw ['N/A', 'N/A', 'N/A', 'N/A', 'N/A']).
    - **s05 ICMP echo flood w/ payload**: det=FAIL bw=N/A. recorded: nothing x5. 0 connection record(s) matched process.
    - **s06 UDP/443 bulk**: det=PASS bw=N/A. recorded: bg_quic x4, nothing x1 (det ['PASS', 'PASS', 'FAIL', 'PASS', 'PASS'], bw ['N/A', 'N/A', 'N/A', 'N/A', 'N/A']).
    - **s07 IPv6 TCP transfer**: det=PASS bw=N/A. recorded: bg_tcp6 x4, nothing x1 (det ['FAIL', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['N/A', 'N/A', 'N/A', 'N/A', 'N/A']).
    - **s09 Small-packet UDP/53 flood**: det=PASS bw=N/A. recorded: bg_dns x4, nothing x1 (det ['PASS', 'PASS', 'PASS', 'FAIL', 'PASS'], bw ['N/A', 'N/A', 'N/A', 'N/A', 'N/A']).
    - **s10 Raw IP socket (proto 253) egress**: det=FAIL bw=N/A. recorded: nothing x5 (det ['PARTIAL', 'FAIL', 'FAIL', 'FAIL', 'FAIL'], bw ['N/A', 'N/A', 'N/A', 'N/A', 'N/A']).
    - **s12 AF_PACKET raw-frame injection**: det=FAIL bw=N/A. recorded: nothing x5. 0 connection record(s) matched process.
    - **s15 sendmmsg batched UDP**: det=PASS bw=N/A. recorded: bg_smmsg x4, nothing x1 (det ['PASS', 'PASS', 'PASS', 'PASS', 'FAIL'], bw ['N/A', 'N/A', 'N/A', 'N/A', 'N/A']).
    - **s16 Loopback-only transfer**: det=FAIL bw=N/A. recorded: nothing x5. 0 connection record(s) matched process.
    - **s17 In-container (docker) egress**: det=FAIL bw=N/A. recorded: nothing x5. 0 connection record(s) matched process.
- **Sniffnet**
    - **s05 ICMP echo flood w/ payload**: det=FAIL bw=FAIL. recorded: nothing x5. no Program row; egress ratio≈0.0.
    - **s08 SCTP transfer**: det=FAIL bw=FAIL. recorded: nothing x5. no Program row; ingress ratio≈0.0.
    - **s10 Raw IP socket (proto 253) egress**: det=FAIL bw=FAIL. recorded: nothing x5. no Program row; egress ratio≈0.0.
    - **s11 Short-lived processes**: det=PARTIAL bw=PASS. recorded: ? x5. listed unattributed (?) by Sniffnet; egress ratio≈1.0022.
    - **s12 AF_PACKET raw-frame injection**: det=PARTIAL bw=PASS. recorded: ? x5. listed unattributed (?) by Sniffnet; egress ratio≈0.9953.
    - **s13 io_uring data path**: det=PARTIAL bw=PASS. recorded: ? x5. listed unattributed (?) by Sniffnet; egress ratio≈0.9876.
    - **s16 Loopback-only transfer**: det=FAIL bw=N/A. recorded: nothing x5. no Program row.
    - **s17 In-container (docker) egress**: det=PARTIAL bw=PASS. recorded: ? x5. listed unattributed (?) by Sniffnet; egress ratio≈0.9874.
    - **s19 Many small TCP connections**: det=PARTIAL bw=PASS. recorded: ? x5. listed unattributed (?) by Sniffnet; egress ratio≈1.0155.
    - **s20 High-rate parallel burst**: det=PARTIAL bw=PASS. recorded: ? x5. listed unattributed (?) by Sniffnet; egress ratio≈1.0078.
    - **s21 io_uring download (recv)**: det=PARTIAL bw=PASS. recorded: ? x5. listed unattributed (?) by Sniffnet; ingress ratio≈1.0709.
- **Little Snitch**
    - **s05 ICMP echo flood w/ payload**: det=PARTIAL bw=FAIL. recorded: another app x4, bg_icmp x1 (det ['PASS', 'PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL'], bw ['FAIL', 'FAIL', 'FAIL', 'FAIL', 'FAIL']).
    - **s09 Small-packet UDP/53 flood**: det=PASS bw=FAIL. recorded: bg_dns x5. WebSocket per-app stats; egress ratio≈0.4705.
    - **s10 Raw IP socket (proto 253) egress**: det=FAIL bw=FAIL. recorded: nothing x5. no matching app row; egress ratio≈0.0.
    - **s12 AF_PACKET raw-frame injection**: det=PARTIAL bw=FAIL. recorded: another app x5. recorded under another application; egress ratio≈0.0.
    - **s13 io_uring data path**: det=PASS bw=FAIL. recorded: bg_uring x5. WebSocket per-app stats; egress ratio≈0.4244.
    - **s16 Loopback-only transfer**: det=FAIL bw=FAIL. recorded: nothing x5. no matching app row; ingress ratio≈0.0.
    - **s17 In-container (docker) egress**: det=PARTIAL bw=FAIL. recorded: another app x5. recorded under another application; egress ratio≈0.0.
    - **s19 Many small TCP connections**: det=PASS bw=PASS. recorded: bg_many x5 (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['PASS', 'PASS', 'PASS', 'PARTIAL', 'PASS']).
    - **s21 io_uring download (recv)**: det=PASS bw=FAIL. recorded: bg_uringdl x5. WebSocket per-app stats; ingress ratio≈0.5091.
- **BCC tcptop**
    - **s22 splice() zero-copy download**: det=PASS bw=FAIL. recorded: bg_splice x5. tcptop per-interval KB summed over the trial; ingress ratio≈0.0.
- **Sysdig**
    - **s13 io_uring data path**: det=PASS bw=FAIL. recorded: bg_uring x5. Sysdig network I/O syscall bytes, per process; egress ratio≈0.0.
    - **s14 sendfile() zero-copy upload**: det=PASS bw=FAIL. recorded: bg_sendf x5. Sysdig network I/O syscall bytes, per process; egress ratio≈0.0.
    - **s21 io_uring download (recv)**: det=PASS bw=FAIL. recorded: bg_uringdl x5. Sysdig network I/O syscall bytes, per process; ingress ratio≈0.0.
    - **s22 splice() zero-copy download**: det=PASS bw=FAIL. recorded: bg_splice x5. Sysdig network I/O syscall bytes, per process; ingress ratio≈0.0.
    - **s23 recvmmsg batched UDP (recv)**: det=PASS bw=FAIL. recorded: bg_rmmsg x5. Sysdig network I/O syscall bytes, per process; ingress ratio≈1.972.
