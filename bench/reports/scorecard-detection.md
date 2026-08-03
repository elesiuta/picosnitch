# Detection scorecard: is the activity seen and attributed to the process?

<!-- --8<-- [start:grid] -->
## Detection

| # | Scenario | picosnitch | NetHogs | bandwhich | OpenSnitch | Sniffnet | Little Snitch | BCC tcplife/tcpconnect | BCC tcptop | bpftrace script | Sysdig |
|---|---|---|---|---|---|---|---|---|---|---|---|
| s01 | TCP bulk download (control) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| s02 | TCP bulk upload | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| s03 | TCP full-duplex up+down | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| s04 | UDP bulk up+down | ✅ | 🟡 | ✅ | ✅* | ✅ | ✅ | ⬜ | ⬜ | ⬜ | ✅ |
| s05 | ICMP echo flood w/ payload | ✅ | ❌ | ❌ | ❌ | ❌ | 🟡* | ⬜ | ⬜ | ⬜ | ✅ |
| s06 | UDP/443 bulk | ✅ | 🟡 | ✅ | ✅* | ✅ | ✅ | ⬜ | ⬜ | ⬜ | ✅ |
| s07 | IPv6 TCP transfer | ✅ | ✅ | ✅ | ✅* | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| s08 | SCTP transfer | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ | ⬜ | ⬜ | ⬜ | ✅ |
| s09 | Small-packet UDP/53 flood | ✅ | 🟡 | ✅ | ❌* | ✅ | ✅ | ⬜ | ⬜ | ⬜ | ✅ |
| s10 | Raw IP socket (proto 253) egress | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ⬜ | ⬜ | ⬜ | ✅ |
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
    - **s04 UDP bulk up+down**: det=PARTIAL bw=PASS. recorded: unknown x5. named 0/0, unknown 25921500/25920800; egress ratio≈1.0.
    - **s05 ICMP echo flood w/ payload**: det=FAIL bw=FAIL. recorded: nothing x5. egress ratio≈0.0.
    - **s06 UDP/443 bulk**: det=PARTIAL bw=PASS. recorded: unknown x5. named 0/0, unknown 25921000/0; egress ratio≈1.0.
    - **s08 SCTP transfer**: det=FAIL bw=FAIL. recorded: nothing x5. ingress ratio≈0.0.
    - **s09 Small-packet UDP/53 flood**: det=PARTIAL bw=PASS. recorded: unknown x5. named 0/0, unknown 6947000/0; egress ratio≈1.0.
    - **s10 Raw IP socket (proto 253) egress**: det=FAIL bw=FAIL. recorded: nothing x5. egress ratio≈0.0.
    - **s11 Short-lived processes**: det=PARTIAL bw=FAIL. recorded: unknown x5. named 0/0, unknown 4863980/35200; egress ratio≈0.4432.
    - **s12 AF_PACKET raw-frame injection**: det=PARTIAL bw=PASS. recorded: unknown x5 (det ['PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL'], bw ['FAIL', 'PASS', 'PASS', 'PASS', 'PASS']).
    - **s13 io_uring data path**: det=PASS bw=PARTIAL. recorded: bg_uring x5. egress ratio≈0.7799.
    - **s15 sendmmsg batched UDP**: det=PARTIAL bw=PASS. recorded: unknown x5. named 0/0, unknown 25933000/0; egress ratio≈1.0.
    - **s17 In-container (docker) egress**: det=PARTIAL bw=PASS. recorded: unknown x5. named 0/0, unknown 26332000/43766; egress ratio≈1.0.
    - **s20 High-rate parallel burst**: det=PARTIAL bw=FAIL. recorded: unknown x5. named 0/0, unknown 2175000/21414; egress ratio≈0.2641.
    - **s21 io_uring download (recv)**: det=PASS bw=PARTIAL. recorded: bg_uringdl x5 (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['PARTIAL', 'PASS', 'PARTIAL', 'PARTIAL', 'PARTIAL']).
    - **s23 recvmmsg batched UDP (recv)**: det=PARTIAL bw=PASS. recorded: unknown x5. named 0/0, unknown 0/25921000; ingress ratio≈1.0.
    - **s24 IPv6 UDP download**: det=PARTIAL bw=PASS. recorded: unknown x5. named 0/0, unknown 0/26281000; ingress ratio≈1.0.
- **bandwhich**
    - **s05 ICMP echo flood w/ payload**: det=FAIL bw=FAIL. recorded: nothing x5. egress ratio≈0.0.
    - **s08 SCTP transfer**: det=FAIL bw=FAIL. recorded: nothing x5. ingress ratio≈0.0.
    - **s10 Raw IP socket (proto 253) egress**: det=FAIL bw=FAIL. recorded: nothing x5. egress ratio≈0.0.
    - **s11 Short-lived processes**: det=PARTIAL bw=PARTIAL. recorded: <UNKNOWN> x5 (det ['PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL'], bw ['PASS', 'PARTIAL', 'PASS', 'PARTIAL', 'PARTIAL']).
    - **s12 AF_PACKET raw-frame injection**: det=PARTIAL bw=PARTIAL. recorded: <UNKNOWN> x5 (det ['PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL'], bw ['PARTIAL', 'PARTIAL', 'PARTIAL', 'PASS', 'PASS']).
    - **s13 io_uring data path**: det=PARTIAL bw=FAIL. recorded: <UNKNOWN> x5 (det ['PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL'], bw ['FAIL', 'FAIL', 'FAIL', 'FAIL', 'PARTIAL']).
    - **s14 sendfile() zero-copy upload**: det=PASS bw=PASS. recorded: bg_sendf x5 (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['PASS', 'PARTIAL', 'PARTIAL', 'PASS', 'PASS']).
    - **s17 In-container (docker) egress**: det=PARTIAL bw=PASS. recorded: <UNKNOWN> x5. named 0/0, <UNKNOWN> 25490019/36171; egress ratio≈0.9906.
    - **s20 High-rate parallel burst**: det=PARTIAL bw=FAIL. recorded: <UNKNOWN> x5. named 0/0, <UNKNOWN> 5375240/28165; egress ratio≈0.6681.
    - **s21 io_uring download (recv)**: det=PARTIAL bw=FAIL. recorded: <UNKNOWN> x5 (det ['PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL'], bw ['FAIL', 'PARTIAL', 'FAIL', 'FAIL', 'PASS']).
- **OpenSnitch**
    - **s04 UDP bulk up+down**: det=PASS bw=N/A. recorded: bg_udp x3, nothing x2 (det ['PASS', 'FAIL', 'PASS', 'PASS', 'FAIL'], bw ['N/A', 'N/A', 'N/A', 'N/A', 'N/A']).
    - **s05 ICMP echo flood w/ payload**: det=FAIL bw=N/A. recorded: nothing x5. 0 connection record(s) matched process.
    - **s06 UDP/443 bulk**: det=PASS bw=N/A. recorded: bg_quic x4, nothing x1 (det ['PASS', 'PASS', 'FAIL', 'PASS', 'PASS'], bw ['N/A', 'N/A', 'N/A', 'N/A', 'N/A']).
    - **s07 IPv6 TCP transfer**: det=PASS bw=N/A. recorded: bg_tcp6 x3, nothing x2 (det ['FAIL', 'FAIL', 'PASS', 'PASS', 'PASS'], bw ['N/A', 'N/A', 'N/A', 'N/A', 'N/A']).
    - **s09 Small-packet UDP/53 flood**: det=FAIL bw=N/A. recorded: nothing x3, bg_dns x2 (det ['PASS', 'FAIL', 'PASS', 'FAIL', 'FAIL'], bw ['N/A', 'N/A', 'N/A', 'N/A', 'N/A']).
    - **s10 Raw IP socket (proto 253) egress**: det=FAIL bw=N/A. recorded: nothing x5. 0 connection record(s) matched process.
    - **s12 AF_PACKET raw-frame injection**: det=FAIL bw=N/A. recorded: nothing x5. 0 connection record(s) matched process.
    - **s15 sendmmsg batched UDP**: det=PASS bw=N/A. recorded: bg_smmsg x3, nothing x2 (det ['PASS', 'FAIL', 'PASS', 'FAIL', 'PASS'], bw ['N/A', 'N/A', 'N/A', 'N/A', 'N/A']).
    - **s16 Loopback-only transfer**: det=FAIL bw=N/A. recorded: nothing x5. 0 connection record(s) matched process.
    - **s17 In-container (docker) egress**: det=FAIL bw=N/A. recorded: nothing x5. 0 connection record(s) matched process.
- **Sniffnet**
    - **s05 ICMP echo flood w/ payload**: det=FAIL bw=FAIL. recorded: nothing x5. no Program row; egress ratio≈0.0.
    - **s08 SCTP transfer**: det=FAIL bw=FAIL. recorded: nothing x5. no Program row; ingress ratio≈0.0.
    - **s10 Raw IP socket (proto 253) egress**: det=FAIL bw=FAIL. recorded: nothing x5. no Program row; egress ratio≈0.0.
    - **s11 Short-lived processes**: det=PARTIAL bw=PASS. recorded: ? x5. listed unattributed (?) by Sniffnet; egress ratio≈1.0023.
    - **s12 AF_PACKET raw-frame injection**: det=PARTIAL bw=PASS. recorded: ? x5. listed unattributed (?) by Sniffnet; egress ratio≈0.9953.
    - **s13 io_uring data path**: det=PARTIAL bw=PASS. recorded: ? x5. listed unattributed (?) by Sniffnet; egress ratio≈0.9876.
    - **s16 Loopback-only transfer**: det=FAIL bw=N/A. recorded: nothing x5. no Program row.
    - **s17 In-container (docker) egress**: det=PARTIAL bw=PASS. recorded: ? x5. listed unattributed (?) by Sniffnet; egress ratio≈0.9874.
    - **s19 Many small TCP connections**: det=PARTIAL bw=PASS. recorded: ? x5. listed unattributed (?) by Sniffnet; egress ratio≈1.0155.
    - **s20 High-rate parallel burst**: det=PARTIAL bw=PASS. recorded: ? x5. listed unattributed (?) by Sniffnet; egress ratio≈1.0077.
    - **s21 io_uring download (recv)**: det=PARTIAL bw=PASS. recorded: ? x5. listed unattributed (?) by Sniffnet; ingress ratio≈1.0708.
- **Little Snitch**
    - **s05 ICMP echo flood w/ payload**: det=PARTIAL bw=FAIL. recorded: another app x4, bg_icmp x1 (det ['PASS', 'PARTIAL', 'PARTIAL', 'PARTIAL', 'PARTIAL'], bw ['FAIL', 'FAIL', 'FAIL', 'FAIL', 'FAIL']).
    - **s09 Small-packet UDP/53 flood**: det=PASS bw=FAIL. recorded: bg_dns x5. WebSocket per-app stats; egress ratio≈0.4778.
    - **s10 Raw IP socket (proto 253) egress**: det=FAIL bw=FAIL. recorded: nothing x5. no matching app row; egress ratio≈0.0.
    - **s12 AF_PACKET raw-frame injection**: det=PARTIAL bw=FAIL. recorded: another app x5. recorded under another application; egress ratio≈0.0.
    - **s13 io_uring data path**: det=PASS bw=FAIL. recorded: bg_uring x5 (det ['PASS', 'PASS', 'PASS', 'PASS', 'PASS'], bw ['PARTIAL', 'FAIL', 'FAIL', 'FAIL', 'FAIL']).
    - **s16 Loopback-only transfer**: det=FAIL bw=FAIL. recorded: nothing x5. no matching app row; ingress ratio≈0.0.
    - **s17 In-container (docker) egress**: det=PARTIAL bw=FAIL. recorded: another app x5. recorded under another application; egress ratio≈0.0.
    - **s21 io_uring download (recv)**: det=PASS bw=FAIL. recorded: bg_uringdl x5. WebSocket per-app stats; ingress ratio≈0.3583.
- **BCC tcptop**
    - **s22 splice() zero-copy download**: det=PASS bw=FAIL. recorded: bg_splice x5. tcptop per-interval KB summed over the trial; ingress ratio≈0.0.
- **Sysdig**
    - **s13 io_uring data path**: det=PASS bw=FAIL. recorded: bg_uring x5. Sysdig network I/O syscall bytes, per process; egress ratio≈0.0.
    - **s14 sendfile() zero-copy upload**: det=PASS bw=FAIL. recorded: bg_sendf x5. Sysdig network I/O syscall bytes, per process; egress ratio≈0.0.
    - **s21 io_uring download (recv)**: det=PASS bw=FAIL. recorded: bg_uringdl x5. Sysdig network I/O syscall bytes, per process; ingress ratio≈0.0.
    - **s22 splice() zero-copy download**: det=PASS bw=FAIL. recorded: bg_splice x5. Sysdig network I/O syscall bytes, per process; ingress ratio≈0.0.
    - **s23 recvmmsg batched UDP (recv)**: det=PASS bw=FAIL. recorded: bg_rmmsg x5. Sysdig network I/O syscall bytes, per process; ingress ratio≈1.9833.
