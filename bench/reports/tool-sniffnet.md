# Sniffnet — detailed results

- layer scored against: **wire** (wire bytes)

- **control (bulk TCP download smoke transfer, separate from the s01 row):** det=PASS bw=PASS (gt recv=33554432, reported recv=36700160)

| # | Scenario | Det | BW | GT app s/r | GT wire s/r | reported s/r | ratio | note |
|---|---|---|---|---|---|---|---|---|
| s01 | TCP bulk download (control) | ✅ PASS | ✅ PASS* | 24/33554432 | 97740/33608000 | -/195035136 | ingress 5.8007 | per-process via GUI OCR (coarse, rounded) |
| s02 | TCP bulk upload | ✅ PASS | ✅ PASS* | 33554456/0 | 34779428/42440 | 295698432/- | egress 8.4222 | per-process via GUI OCR (coarse, rounded) |
| s03 | TCP full-duplex up+down | ✅ PASS | ⬜ N/A | 25165872/25165824 | 26211764/25235468 | -/- |  | per-process via GUI OCR; one combined total, cannot split direction |
| s04 | UDP bulk up+down | ✅ PASS | ⬜ N/A | 25166448/25165824 | 25669832/25669152 | -/- |  | per-process via GUI OCR; one combined total, cannot split direction |
| s05 | ICMP echo flood w/ payload | 🟡 PART | ✅ PASS | 6342336/6468176 | 6468176/6468176 | 6342336/6342336 | egress 0.9674 | flow-level (pcap); process not read from GUI |
| s06 | UDP/443 bulk | ✅ PASS | ✅ PASS* | 25166424/0 | 25669780/0 | 1932735283.2/- | egress 74.5612 | per-process via GUI OCR (coarse, rounded) |
| s07 | IPv6 TCP transfer | ✅ PASS* | ✅ PASS* | 24/25165824 | 95360/25221560 | 24/25165824 | ingress 0.9974 | flow-level (pcap); process not read from GUI |
| s08 | SCTP transfer | ✅ PASS | 🟡 PART | 24/25165824 | 424472/25572252 | -/28311552 | ingress 1.1048 | per-process via GUI OCR (coarse, rounded) |
| s09 | Small-packet UDP/53 flood | ✅ PASS | ✅ PASS* | 4194328/0 | 6029364/0 | 7235174.4/- | egress 1.0415 | per-process via GUI OCR (coarse, rounded) |
| s10 | Raw IP socket (proto 253) egress | 🟡 PART | ❌ FAIL | 4194304/0 | 4254224/0 | 0/0 | egress 0.0 | flow-level (pcap); process not read from GUI |
| s11 | Short-lived processes | 🟡 PART | ✅ PASS | 10486240/0 | 10871096/60076 | 10486240/0 | egress 0.9555 | flow-level (pcap); process not read from GUI |
| s12 | AF_PACKET raw-frame injection | 🟡 PART | ✅ PASS | 4194304/0 | 4278192/0 | 4194304/0 | egress 0.9709 | flow-level (pcap); process not read from GUI |
| s13 | io_uring data path | 🟡 PART | ✅ PASS* | 25165848/0 | 26079652/40516 | 25165848/0 | egress 0.9559 | flow-level (pcap); process not read from GUI |
| s14 | sendfile() zero-copy upload | ✅ PASS | ✅ PASS* | 33554456/0 | 34779376/35004 | 1932735283.2/- | egress 55.0493 | per-process via GUI OCR (coarse, rounded) |
| s15 | sendmmsg batched UDP | ✅ PASS | ✅ PASS* | 25177624/0 | 25681204/0 | 321912832/- | egress 12.4133 | per-process via GUI OCR (coarse, rounded) |
| s16 | Loopback-only transfer | 🟡 PART | ❌ FAIL | 24/25165824 | 24/25165824 | 25165848/0 | ingress 0.0 | flow-level (pcap); process not read from GUI |
| s17 | In-container (docker) egress | 🟡 PART | ❌ FAIL | 25165848/0 | 26084644/37448 | 75497544/0 | egress 2.8671 | flow-level (pcap); process not read from GUI |
| s18 | Low-and-slow drip upload | ✅ PASS* | ✅ PASS* | 2097176/0 | 2173988/29336 | 2097176/0 | egress 0.9556 | flow-level (pcap); process not read from GUI |
| s19 | Many small TCP connections | 🟡 PART | ✅ PASS | 3933600/0 | 4093200/75308 | 3933600/0 | egress 0.9511 | flow-level (pcap); process not read from GUI |
| s20 | High-rate parallel burst | 🟡 PART | ✅ PASS* | 7865040/0 | 8157832/71272 | 7865040/0 | egress 0.9549 | flow-level (pcap); process not read from GUI |
| s21 | io_uring download (recv) | ✅ PASS* | ✅ PASS* | 24/25165824 | 213340/25201028 | 24/25167272 | ingress 0.9983 | flow-level (pcap); process not read from GUI |
| s22 | splice() zero-copy download | ✅ PASS | ✅ PASS* | 24/33554432 | 235280/33608000 | -/1717986918.4 | ingress 51.0965 | per-process via GUI OCR (coarse, rounded) |
| s23 | recvmmsg batched UDP (recv) | ✅ PASS | ✅ PASS* | 24/25165824 | 52/25669152 | -/457179136 | ingress 17.6375 | per-process via GUI OCR (coarse, rounded) |
| s24 | IPv6 UDP download | ✅ PASS | ✅ PASS* | 24/25165824 | 72/26028672 | -/593494016 | ingress 22.5832 | per-process via GUI OCR (coarse, rounded) |

⚡/\* rows: trials disagreed; the table shows the first trial's numbers, while the verdict combines all trials (best of 5 for Sniffnet).
