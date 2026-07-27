# NetHogs — detailed results

- layer scored against: **wire** (wire bytes)

- **control (bulk TCP download smoke transfer, separate from the s01 row):** det=PASS bw=PASS (gt recv=33554432, reported recv=35109100)

| # | Scenario | Det | BW | GT app s/r | GT wire s/r | reported s/r | ratio | note |
|---|---|---|---|---|---|---|---|---|
| s01 | TCP bulk download (control) | ✅ PASS | ✅ PASS | 24/33554432 | 58532/33608000 | 74348/35109100 | ingress 1.0442 |  |
| s02 | TCP bulk upload | ✅ PASS | ✅ PASS | 33554456/0 | 34779428/47900 | 35109200/60794 | egress 1.0 |  |
| s03 | TCP full-duplex up+down | ✅ PASS | ✅ PASS | 25165872/25165824 | 26135376/25239524 | 26332000/26331900 | egress 0.9976 |  |
| s04 | UDP bulk up+down | 🟡 PART | ✅ PASS | 25166448/25165824 | 25669832/25669152 | 25921482/25920850 | egress 1.0 | bucketed as unknown |
| s05 | ICMP echo flood w/ payload | ❌ FAIL | ❌ FAIL | 6342336/6468176 | 6468176/6468176 | 0/0 | egress 0.0 | not detected |
| s06 | UDP/443 bulk | 🟡 PART | ✅ PASS | 25166424/0 | 25669780/0 | 25922000/0 | egress 1.0 | bucketed as unknown |
| s07 | IPv6 TCP transfer | ✅ PASS | ✅ PASS | 24/25165824 | 64472/25221560 | 77088/26685200 | ingress 1.0576 |  |
| s08 | SCTP transfer | ❌ FAIL | ❌ FAIL | 24/25165824 | 424472/25572252 | 0/0 | ingress 0.0 | not detected |
| s09 | Small-packet UDP/53 flood | 🟡 PART | ✅ PASS | 4194328/0 | 6029364/0 | 6947000/0 | egress 1.0 | bucketed as unknown |
| s10 | Raw IP socket (proto 253) egress | ❌ FAIL | ❌ FAIL | 4194304/0 | 4254224/0 | 0/0 | egress 0.0 | not detected |
| s11 | Short-lived processes | 🟡 PART | ❌ FAIL | 10486240/0 | 10871044/49820 | 3820890/30218 | egress 0.3482 | bucketed as unknown |
| s12 | AF_PACKET raw-frame injection | 🟡 PART | ✅ PASS⚡ | 4194304/0 | 4278192/0 | 3772000/0 | egress 0.8731 | bucketed as unknown |
| s13 | io_uring data path | ✅ PASS | 🟡 PART | 25165848/0 | 26084436/30012 | 20266800/31622 | egress 0.7697 |  |
| s14 | sendfile() zero-copy upload | ✅ PASS | ✅ PASS | 33554456/0 | 34779376/34900 | 35109200/44294 | egress 1.0 |  |
| s15 | sendmmsg batched UDP | 🟡 PART | ✅ PASS | 25177624/0 | 25681204/0 | 25933000/0 | egress 1.0 | bucketed as unknown |
| s16 | Loopback-only transfer | ✅ PASS | ❌ FAIL | 24/25165824 | 24/25165824 | 27752/0 | ingress 0.0 |  |
| s17 | In-container (docker) egress | 🟡 PART | ✅ PASS | 25165848/0 | 26084644/40204 | 26332000/51026 | egress 1.0 | bucketed as unknown |
| s18 | Low-and-slow drip upload | ✅ PASS | ✅ PASS | 2097176/0 | 2173988/30844 | 2194670/39146 | egress 1.0 |  |
| s19 | Many small TCP connections | ✅ PASS | ❌ FAIL | 3933600/0 | 4093200/75152 | 1378680/31708 | egress 0.3333 |  |
| s20 | High-rate parallel burst | 🟡 PART | ❌ FAIL | 7865040/0 | 8157884/54320 | 1956000/20136 | egress 0.2375 | bucketed as unknown |
| s21 | io_uring download (recv) | ✅ PASS | ✅ PASS⚡ | 24/25165824 | 266792/25206184 | 303896/23803800 | ingress 0.944 |  |
| s22 | splice() zero-copy download | ✅ PASS | ✅ PASS | 24/33554432 | 89368/33607948 | 113486/35109100 | ingress 1.0442 |  |
| s23 | recvmmsg batched UDP (recv) | 🟡 PART | ✅ PASS | 24/25165824 | 52/25669152 | 1000/25921000 | ingress 1.0 | bucketed as unknown |
| s24 | IPv6 UDP download | 🟡 PART | ✅ PASS | 24/25165824 | 72/26028672 | 0/26280000 | ingress 1.0 | bucketed as unknown |

⚡/\* rows: trials disagreed; the table shows the first trial's numbers, while the verdict combines all trials (best of 5 for Sniffnet).
