# Sniffnet: detailed results

- layer scored against: **wire** (wire bytes)

- **control (separate from the s01 row):** det=PASS bw=PASS (ref recv=33554432, reported recv=36700160)

| # | Scenario | Det | BW | ref app s/r | ref wire s/r | reported s/r | ratio | note |
|---|---|---|---|---|---|---|---|---|
| s01 | TCP bulk download (control) | ✅ PASS | ✅ PASS | 24/33554432 | 73404/33608052 | -/36700160 | ingress 1.0915 | per-program total from the GUI |
| s02 | TCP bulk upload | ✅ PASS | ✅ PASS | 33554456/0 | 34779428/37188 | 36700160/- | egress 1.0453 | per-program total from the GUI |
| s03 | TCP full-duplex up+down | ✅ PASS | ⬜ N/A | 25165872/25165824 | 26160180/25233388 | -/- |  | per-program total from the GUI; one combined figure, cannot split direction |
| s04 | UDP bulk up+down | ✅ PASS | ⬜ N/A | 25166448/25165824 | 25669832/25669152 | -/- |  | per-program total from the GUI; one combined figure, cannot split direction |
| s05 | ICMP echo flood w/ payload | ❌ FAIL | ❌ FAIL | 6342336/6468176 | 6468176/6468176 | 0/0 | egress 0.0 | no Program row |
| s06 | UDP/443 bulk | ✅ PASS | ✅ PASS | 25166424/0 | 25669780/0 | 27262976/- | egress 1.0518 | per-program total from the GUI |
| s07 | IPv6 TCP transfer | ✅ PASS | 🟡 PART | 24/25165824 | 67496/25221704 | -/28311552 | ingress 1.122 | per-program total from the GUI |
| s08 | SCTP transfer | ❌ FAIL | ❌ FAIL | 24/25165824 | 424472/25572252 | 0/0 | ingress 0.0 | no Program row |
| s09 | Small-packet UDP/53 flood | ✅ PASS | ✅ PASS | 4194328/0 | 6029364/0 | 7235174.4/- | egress 1.0415 | per-program total from the GUI |
| s10 | Raw IP socket (proto 253) egress | ❌ FAIL | ❌ FAIL | 4194304/0 | 4254224/0 | 0/0 | egress 0.0 | no Program row |
| s11 | Short-lived processes | 🟡 PART | ✅ PASS | 10486240/0 | 10871200/48012 | 11534336/- | egress 1.051 | listed unattributed (?) by Sniffnet |
| s12 | AF_PACKET raw-frame injection | 🟡 PART | ✅ PASS | 4194304/0 | 4278192/0 | 4508876.8/- | egress 1.0437 | listed unattributed (?) by Sniffnet |
| s13 | io_uring data path | 🟡 PART | ✅ PASS | 25165848/0 | 26085104/42800 | 27262976/- | egress 1.0353 | listed unattributed (?) by Sniffnet |
| s14 | sendfile() zero-copy upload | ✅ PASS | ✅ PASS | 33554456/0 | 34779428/41192 | 36700160/- | egress 1.0453 | per-program total from the GUI |
| s15 | sendmmsg batched UDP | ✅ PASS | ✅ PASS | 25177624/0 | 25681204/0 | 27262976/- | egress 1.0513 | per-program total from the GUI |
| s16 | Loopback-only transfer | ❌ FAIL | ❌ FAIL | 24/25165824 | 24/25165824 | 0/0 | ingress 0.0 | no Program row |
| s17 | In-container (docker) egress | 🟡 PART | ✅ PASS | 25165848/0 | 26084644/27152 | 27262976/- | egress 1.0354 | listed unattributed (?) by Sniffnet |
| s18 | Low-and-slow drip upload | ✅ PASS | ✅ PASS | 2097176/0 | 2173988/27256 | 2306867.2/- | egress 1.0511 | per-program total from the GUI |
| s19 | Many small TCP connections | 🟡 PART | ✅ PASS | 3933600/0 | 4093200/75360 | 4404019.2/- | egress 1.0648 | listed unattributed (?) by Sniffnet |
| s20 | High-rate parallel burst | 🟡 PART | ✅ PASS* | 7865040/0 | 8157520/51720 | 8703180.8/- | egress 1.0567 | listed unattributed (?) by Sniffnet |
| s21 | io_uring download (recv) | 🟡 PART | 🟡 PART | 24/25165824 | 222904/25205404 | -/28311552 | ingress 1.1228 | listed unattributed (?) by Sniffnet |
| s22 | splice() zero-copy download | ✅ PASS | ✅ PASS | 24/33554432 | 165236/33607948 | -/36700160 | ingress 1.0915 | per-program total from the GUI |
| s23 | recvmmsg batched UDP (recv) | ✅ PASS | ✅ PASS | 24/25165824 | 52/25669152 | -/27262976 | ingress 1.0518 | per-program total from the GUI |
| s24 | IPv6 UDP download | ✅ PASS | ✅ PASS | 24/25165824 | 72/26028672 | -/27262976 | ingress 1.0374 | per-program total from the GUI |

Rows show the first trial's numbers; verdicts combine all trials. \* = trials disagreed.
