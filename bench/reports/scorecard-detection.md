# Detection scorecard: is the activity seen and attributed to the process?

<!-- --8<-- [start:grid] -->
## Detection

| # | Scenario | picosnitch | NetHogs | bandwhich | OpenSnitch | Sniffnet | Little Snitch | BCC tcplife/tcpconnect | BCC tcptop | bpftrace script | Sysdig |
|---|---|---|---|---|---|---|---|---|---|---|---|
| s01 | TCP bulk download (control) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| s02 | TCP bulk upload | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| s03 | TCP full-duplex up+down | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| s04 | UDP bulk up+down | ✅ | 🟡 | ✅ | ✅* | ✅ | ✅ | ⬜ | ⬜ | ⬜ | ✅ |
| s05 | ICMP echo flood w/ payload | ✅ | ❌ | ❌* | ❌ | ❌ | 🟡* | ⬜ | ⬜ | ⬜ | ✅ |
| s06 | UDP/443 bulk | ✅ | 🟡 | ✅ | ✅* | ✅ | ✅ | ⬜ | ⬜ | ⬜ | ✅ |
| s07 | IPv6 TCP transfer | ✅ | ✅ | ✅ | ✅* | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| s08 | SCTP transfer | ✅ | ❌* | ❌* | ✅ | ❌ | ✅ | ⬜ | ⬜ | ⬜ | ✅ |
| s09 | Small-packet UDP/53 flood | ✅ | 🟡 | ✅ | ✅* | ✅ | ✅ | ⬜ | ⬜ | ⬜ | ✅ |
| s10 | Raw IP socket (proto 253) egress | ✅ | ❌ | ❌* | ❌ | ❌ | ❌ | ⬜ | ⬜ | ⬜ | ✅ |
| s11 | Short-lived processes | ✅ | 🟡 | 🟡 | ✅ | 🟡 | ✅ | ✅ | ✅ | ✅ | ✅ |
| s12 | AF_PACKET raw-frame injection | ❌ | 🟡 | 🟡 | ❌ | 🟡 | 🟡 | ⬜ | ⬜ | ⬜ | ✅ |
| s13 | io_uring data path | ✅ | ✅ | 🟡 | ✅ | 🟡 | ✅ | ✅ | ✅ | ✅ | ✅ |
| s14 | sendfile() zero-copy upload | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| s15 | sendmmsg batched UDP | ✅ | 🟡 | ✅ | ✅* | ✅ | ✅ | ⬜ | ⬜ | ⬜ | ✅ |
| s16 | Loopback-only transfer | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ |
| s17 | In-container (docker) egress | ✅ | 🟡 | 🟡 | ❌ | 🟡 | 🟡 | ✅ | ✅ | ✅ | ✅ |
| s18 | Low-and-slow drip upload | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| s19 | Many small TCP connections | ✅ | ✅ | ✅ | ✅ | 🟡 | ✅ | ✅ | ✅ | ✅ | ✅ |
| s20 | High-rate parallel burst | ✅ | 🟡 | 🟡 | ✅ | 🟡 | ✅ | ✅ | ✅ | ✅ | ✅ |
| s21 | io_uring download (recv) | ✅ | ✅ | 🟡 | ✅ | 🟡 | ✅ | ✅ | ✅ | ✅ | ✅ |
| s22 | splice() zero-copy download | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| s23 | recvmmsg batched UDP (recv) | ✅ | 🟡 | ✅ | ✅ | ✅ | ✅ | ⬜ | ⬜ | ⬜ | ✅ |
| s24 | IPv6 UDP download | ✅ | 🟡 | ✅ | ✅ | ✅ | ✅ | ⬜ | ⬜ | ⬜ | ✅ |

Legend: ✅ PASS · 🟡 PARTIAL · ❌ FAIL · ⬜ N/A · ⚠️ error · \* trials disagreed, see the note

<!-- --8<-- [end:grid] -->
## Result notes

- **picosnitch**
    - **s12 AF_PACKET raw-frame injection**: det=FAIL bw=FAIL. recorded: nothing x5. egress ratio≈0.0.
- **NetHogs**
    - **s04 UDP bulk up+down**: det=PARTIAL bw=PASS. recorded: unknown x5. named 0/0, unknown 25921510/25920834; egress ratio≈1.0.
    - **s05 ICMP echo flood w/ payload**: det=FAIL bw=FAIL. recorded: nothing x5. egress ratio≈0.0.
    - **s06 UDP/443 bulk**: det=PARTIAL bw=PASS. recorded: unknown x5. named 0/0, unknown 25922000/0; egress ratio≈1.0.
    - **s08 SCTP transfer**: det=FAIL bw=FAIL. recorded: nothing x4, unknown x1 (det ['FAIL', 'FAIL', 'PARTIAL', 'FAIL', 'FAIL'], bw ['FAIL', 'FAIL', 'FAIL', 'FAIL', 'FAIL']).
    - **s09 Small-packet UDP/53 flood**: det=PARTIAL bw=PASS. recorded: unknown x5. named 0/0, unknown 6947000/0; egress ratio≈1.0.
    - **s10 Raw IP socket (proto 253) egress**: det=FAIL bw=FAIL. recorded: nothing x5. egress ratio≈0.0.
    - **s11 Short-lived processes**: det=PARTIAL bw=FAIL. recorded: unknown x5. named 0/0, unknown 4370460/32816; egress ratio≈0.3982.
    - **s12 AF_PACKET raw-frame injection**: det=PARTIAL bw=PASS. recorded: unknown x5 (det ['PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL'], bw ['FAIL', 'PASS', 'PASS', 'PASS', 'PASS']).
    - **s13 io_uring data path**: det=PASS bw=PARTIAL. recorded: bg_uring x5. egress ratio≈0.7956.
    - **s15 sendmmsg batched UDP**: det=PARTIAL bw=PASS. recorded: unknown x5. named 0/0, unknown 25933000/0; egress ratio≈1.0.
    - **s17 In-container (docker) egress**: det=PARTIAL bw=PASS. recorded: unknown x5. named 0/0, unknown 26332000/41522; egress ratio≈1.0.
    - **s20 High-rate parallel burst**: det=PARTIAL bw=FAIL. recorded: unknown x5. named 0/0, unknown 2087000/21514; egress ratio≈0.2534.
    - **s21 io_uring download (recv)**: det=PASS bw=PASS. recorded: bg_uringdl x5 (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['PASS', 'PARTIAL', 'PASS', 'PASS', 'PARTIAL']).
    - **s23 recvmmsg batched UDP (recv)**: det=PARTIAL bw=PASS. recorded: unknown x5. named 0/0, unknown 0/25921000; ingress ratio≈1.0.
    - **s24 IPv6 UDP download**: det=PARTIAL bw=PASS. recorded: unknown x5. named 0/0, unknown 0/26280000; ingress ratio≈1.0.
- **bandwhich**
    - **s05 ICMP echo flood w/ payload**: det=FAIL bw=FAIL. recorded: nothing x4, <UNKNOWN> x1 (det ['PARTIAL', 'FAIL', 'FAIL', 'FAIL', 'FAIL'], bw ['FAIL', 'FAIL', 'FAIL', 'FAIL', 'FAIL']).
    - **s08 SCTP transfer**: det=FAIL bw=FAIL. recorded: nothing x4, <UNKNOWN> x1 (det ['PARTIAL', 'FAIL', 'FAIL', 'FAIL', 'FAIL'], bw ['FAIL', 'FAIL', 'FAIL', 'FAIL', 'FAIL']).
    - **s10 Raw IP socket (proto 253) egress**: det=FAIL bw=FAIL. recorded: nothing x4, <UNKNOWN> x1 (det ['PARTIAL', 'FAIL', 'FAIL', 'FAIL', 'FAIL'], bw ['FAIL', 'FAIL', 'FAIL', 'FAIL', 'FAIL']).
    - **s11 Short-lived processes**: det=PARTIAL bw=PASS. recorded: <UNKNOWN> x5 (det ['PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL'], bw ['PARTIAL', 'PARTIAL', 'PASS', 'PASS', 'PASS']).
    - **s12 AF_PACKET raw-frame injection**: det=PARTIAL bw=PASS. recorded: <UNKNOWN> x5 (det ['PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL'], bw ['PASS', 'PASS', 'PARTIAL', 'PARTIAL', 'PASS']).
    - **s13 io_uring data path**: det=PARTIAL bw=FAIL. recorded: <UNKNOWN> x5 (det ['PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL'], bw ['FAIL', 'FAIL', 'PARTIAL', 'FAIL', 'FAIL']).
    - **s14 sendfile() zero-copy upload**: det=PASS bw=PARTIAL. recorded: bg_sendf x5 (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['PASS', 'PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL']).
    - **s17 In-container (docker) egress**: det=PARTIAL bw=PASS. recorded: <UNKNOWN> x5. named 0/0, <UNKNOWN> 25235388/36864; egress ratio≈0.9807.
    - **s18 Low-and-slow drip upload**: det=PASS bw=PASS. recorded: bg_slow x5 (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['FAIL', 'PASS', 'PASS', 'PASS', 'PASS']).
    - **s20 High-rate parallel burst**: det=PARTIAL bw=FAIL. recorded: <UNKNOWN> x5. named 0/0, <UNKNOWN> 4558840/21550; egress ratio≈0.5666.
    - **s21 io_uring download (recv)**: det=PARTIAL bw=PARTIAL. recorded: <UNKNOWN> x5 (det ['PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL'], bw ['PASS', 'PARTIAL', 'FAIL', 'PARTIAL', 'PASS']).
- **OpenSnitch**
    - **s04 UDP bulk up+down**: det=PASS bw=N/A. recorded: bg_udp x4, nothing x1 (det ['PASS', 'PASS', 'FAIL', 'PASS', 'PASS'], bw ['N/A', 'N/A', 'N/A', 'N/A', 'N/A']).
    - **s05 ICMP echo flood w/ payload**: det=FAIL bw=N/A. recorded: nothing x5. 0 connection record(s) matched process.
    - **s06 UDP/443 bulk**: det=PASS bw=N/A. recorded: bg_quic x4, nothing x1 (det ['PASS', 'PASS', 'FAIL', 'PASS', 'PASS'], bw ['N/A', 'N/A', 'N/A', 'N/A', 'N/A']).
    - **s07 IPv6 TCP transfer**: det=PASS bw=N/A. recorded: bg_tcp6 x4, nothing x1 (det ['FAIL', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['N/A', 'N/A', 'N/A', 'N/A', 'N/A']).
    - **s09 Small-packet UDP/53 flood**: det=PASS bw=N/A. recorded: bg_dns x3, nothing x2 (det ['PASS', 'PASS', 'FAIL', 'FAIL', 'PASS'], bw ['N/A', 'N/A', 'N/A', 'N/A', 'N/A']).
    - **s10 Raw IP socket (proto 253) egress**: det=FAIL bw=N/A. recorded: nothing x5. 0 connection record(s) matched process.
    - **s12 AF_PACKET raw-frame injection**: det=FAIL bw=N/A. recorded: nothing x5. 0 connection record(s) matched process.
    - **s15 sendmmsg batched UDP**: det=PASS bw=N/A. recorded: bg_smmsg x3, nothing x2 (det ['PASS', 'FAIL', 'PASS', 'PASS', 'FAIL'], bw ['N/A', 'N/A', 'N/A', 'N/A', 'N/A']).
    - **s16 Loopback-only transfer**: det=FAIL bw=N/A. recorded: nothing x5. 0 connection record(s) matched process.
    - **s17 In-container (docker) egress**: det=FAIL bw=N/A. recorded: nothing x5. 0 connection record(s) matched process.
- **Sniffnet**
    - **s05 ICMP echo flood w/ payload**: det=FAIL bw=FAIL. recorded: nothing x5. no Program row; egress ratio≈0.0.
    - **s08 SCTP transfer**: det=FAIL bw=FAIL. recorded: nothing x5. no Program row; ingress ratio≈0.0.
    - **s10 Raw IP socket (proto 253) egress**: det=FAIL bw=FAIL. recorded: nothing x5. no Program row; egress ratio≈0.0.
    - **s11 Short-lived processes**: det=PARTIAL bw=PASS. recorded: ? x5. listed unattributed (?) by Sniffnet; egress ratio≈1.0022.
    - **s12 AF_PACKET raw-frame injection**: det=PARTIAL bw=PASS. recorded: ? x5. listed unattributed (?) by Sniffnet; egress ratio≈0.9953.
    - **s13 io_uring data path**: det=PARTIAL bw=PASS. recorded: ? x5. listed unattributed (?) by Sniffnet; egress ratio≈0.9875.
    - **s16 Loopback-only transfer**: det=FAIL bw=N/A. recorded: nothing x5. no Program row.
    - **s17 In-container (docker) egress**: det=PARTIAL bw=PASS. recorded: ? x5. listed unattributed (?) by Sniffnet; egress ratio≈0.9874.
    - **s19 Many small TCP connections**: det=PARTIAL bw=PASS. recorded: ? x5. listed unattributed (?) by Sniffnet; egress ratio≈1.0155.
    - **s20 High-rate parallel burst**: det=PARTIAL bw=PASS. recorded: ? x5. listed unattributed (?) by Sniffnet; egress ratio≈1.0078.
    - **s21 io_uring download (recv)**: det=PARTIAL bw=PASS. recorded: ? x5. listed unattributed (?) by Sniffnet; ingress ratio≈1.0708.
- **Little Snitch**
    - **s05 ICMP echo flood w/ payload**: det=PARTIAL bw=FAIL. recorded: another app x4, bg_icmp x1 (det ['PASS', 'PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL'], bw ['FAIL', 'FAIL', 'FAIL', 'FAIL', 'FAIL']).
    - **s09 Small-packet UDP/53 flood**: det=PASS bw=FAIL. recorded: bg_dns x5. WebSocket per-app stats; egress ratio≈0.4516.
    - **s10 Raw IP socket (proto 253) egress**: det=FAIL bw=FAIL. recorded: nothing x5. no matching app row; egress ratio≈0.0.
    - **s12 AF_PACKET raw-frame injection**: det=PARTIAL bw=FAIL. recorded: another app x5. recorded under another application; egress ratio≈0.0.
    - **s13 io_uring data path**: det=PASS bw=FAIL. recorded: bg_uring x5. WebSocket per-app stats; egress ratio≈0.5755.
    - **s16 Loopback-only transfer**: det=FAIL bw=FAIL. recorded: nothing x5. no matching app row; ingress ratio≈0.0.
    - **s17 In-container (docker) egress**: det=PARTIAL bw=FAIL. recorded: another app x5. recorded under another application; egress ratio≈0.0.
    - **s21 io_uring download (recv)**: det=PASS bw=FAIL. recorded: bg_uringdl x5. WebSocket per-app stats; ingress ratio≈0.3094.
- **BCC tcptop**
    - **s22 splice() zero-copy download**: det=PASS bw=FAIL. recorded: bg_splice x5. tcptop per-interval KB summed over the trial; ingress ratio≈0.0.
- **Sysdig**
    - **s13 io_uring data path**: det=PASS bw=FAIL. recorded: bg_uring x5. Sysdig network I/O syscall bytes, per process; egress ratio≈0.0.
    - **s14 sendfile() zero-copy upload**: det=PASS bw=FAIL. recorded: bg_sendf x5. Sysdig network I/O syscall bytes, per process; egress ratio≈0.0.
    - **s21 io_uring download (recv)**: det=PASS bw=FAIL. recorded: bg_uringdl x5. Sysdig network I/O syscall bytes, per process; ingress ratio≈0.0.
    - **s22 splice() zero-copy download**: det=PASS bw=FAIL. recorded: bg_splice x5. Sysdig network I/O syscall bytes, per process; ingress ratio≈0.0.
