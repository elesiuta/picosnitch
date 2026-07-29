# picosnitch: detailed results

- layer scored against: **socket** (app-layer bytes)

- **control (separate from the s01 row):** det=PASS bw=PASS (ref recv=33554432, reported recv=33554432)

| # | Scenario | Det | BW | ref app s/r | ref wire s/r | reported s/r | ratio | note |
|---|---|---|---|---|---|---|---|---|
| s01 | TCP bulk download (control) | ✅ PASS | ✅ PASS | 24/33554432 | 64096/33608108 | 24/33554432 | ingress 1.0 |  |
| s02 | TCP bulk upload | ✅ PASS | ✅ PASS | 33554456/0 | 34779428/39944 | 33095704/0 | egress 0.9863 |  |
| s03 | TCP full-duplex up+down | ✅ PASS | ✅ PASS | 25165872/25165824 | 26121440/25237964 | 25165872/25165824 | egress 1.0 |  |
| s04 | UDP bulk up+down | ✅ PASS | ✅ PASS | 25166448/25165824 | 25669832/25669152 | 25166448/25165824 | egress 1.0 |  |
| s05 | ICMP echo flood w/ payload | ✅ PASS | ✅ PASS | 6342336/6468176 | 6468176/6468176 | 6342336/6468176 | egress 1.0 |  |
| s06 | UDP/443 bulk | ✅ PASS | ✅ PASS | 25166424/0 | 25669780/0 | 25166424/0 | egress 1.0 |  |
| s07 | IPv6 TCP transfer | ✅ PASS | ✅ PASS | 24/25165824 | 47192/25221616 | 24/25165824 | ingress 1.0 |  |
| s08 | SCTP transfer | ✅ PASS | ✅ PASS | 24/25165824 | 424472/25572252 | 24/25165824 | ingress 1.0 |  |
| s09 | Small-packet UDP/53 flood | ✅ PASS | ✅ PASS | 4194328/0 | 6029364/0 | 4194328/0 | egress 1.0 |  |
| s10 | Raw IP socket (proto 253) egress | ✅ PASS | ✅ PASS | 4194304/0 | 4254224/0 | 4194304/0 | egress 1.0 |  |
| s11 | Short-lived processes | ✅ PASS | ✅ PASS | 10486240/0 | 10871460/43476 | 10486240/0 | egress 1.0 |  |
| s12 | AF_PACKET raw-frame injection | ❌ FAIL | ❌ FAIL | 4194304/0 | 4278192/0 | 0/0 | egress 0.0 |  |
| s13 | io_uring data path | ✅ PASS | ✅ PASS | 25165848/0 | 26083500/29388 | 25165848/0 | egress 1.0 |  |
| s14 | sendfile() zero-copy upload | ✅ PASS | ✅ PASS | 33554456/0 | 34779428/35992 | 33554456/0 | egress 1.0 |  |
| s15 | sendmmsg batched UDP | ✅ PASS | ✅ PASS | 25177624/0 | 25681204/0 | 25177624/0 | egress 1.0 |  |
| s16 | Loopback-only transfer | ✅ PASS | ✅ PASS | 24/25165824 | 24/25165824 | 24/25165824 | ingress 1.0 |  |
| s17 | In-container (docker) egress | ✅ PASS | ✅ PASS | 25165848/0 | 26084644/41608 | 25165848/0 | egress 1.0 |  |
| s18 | Low-and-slow drip upload | ✅ PASS | ✅ PASS | 2097176/0 | 2173988/30272 | 2097176/0 | egress 1.0 |  |
| s19 | Many small TCP connections | ✅ PASS | ✅ PASS | 3933600/0 | 4093200/74788 | 3933600/0 | egress 1.0 |  |
| s20 | High-rate parallel burst | ✅ PASS | ✅ PASS | 7865040/0 | 8157884/53696 | 7865040/0 | egress 1.0 |  |
| s21 | io_uring download (recv) | ✅ PASS | ✅ PASS | 24/25165824 | 166016/25206132 | 24/25165824 | ingress 1.0 |  |
| s22 | splice() zero-copy download | ✅ PASS | ✅ PASS | 24/33554432 | 85676/33608000 | 24/33554432 | ingress 1.0 |  |
| s23 | recvmmsg batched UDP (recv) | ✅ PASS | ✅ PASS | 24/25165824 | 52/25669152 | 24/25165824 | ingress 1.0 |  |
| s24 | IPv6 UDP download | ✅ PASS | ✅ PASS | 24/25165824 | 72/26028672 | 24/25165824 | ingress 1.0 |  |
