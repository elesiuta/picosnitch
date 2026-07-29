# NetHogs: detailed results

- layer scored against: **wire** (wire bytes)

- **control (separate from the s01 row):** det=PASS bw=PASS (ref recv=33554432, reported recv=35109100)

| # | Scenario | Det | BW | ref app s/r | ref wire s/r | reported s/r | ratio | note |
|---|---|---|---|---|---|---|---|---|
| s01 | TCP bulk download (control) | ✅ PASS | ✅ PASS | 24/33554432 | 90616/33608052 | 115070/35109100 | ingress 1.0442 |  |
| s02 | TCP bulk upload | ✅ PASS | ✅ PASS | 33554456/0 | 34779428/41504 | 35109200/52676 | egress 1.0 |  |
| s03 | TCP full-duplex up+down | ✅ PASS | ✅ PASS | 25165872/25165824 | 26148688/25239992 | 26332000/26331900 | egress 0.9969 |  |
| s04 | UDP bulk up+down | 🟡 PART | ✅ PASS | 25166448/25165824 | 25669832/25669152 | 25921524/25920780 | egress 1.0 | bucketed as unknown |
| s05 | ICMP echo flood w/ payload | ❌ FAIL | ❌ FAIL | 6342336/6468176 | 6468176/6468176 | 0/0 | egress 0.0 | not detected |
| s06 | UDP/443 bulk | 🟡 PART | ✅ PASS | 25166424/0 | 25669780/0 | 25921000/0 | egress 1.0 | bucketed as unknown |
| s07 | IPv6 TCP transfer | ✅ PASS | ✅ PASS | 24/25165824 | 72392/25221560 | 86548/26685200 | ingress 1.0576 |  |
| s08 | SCTP transfer | ❌ FAIL | ❌ FAIL | 24/25165824 | 424472/25572252 | 0/0 | ingress 0.0 | not detected |
| s09 | Small-packet UDP/53 flood | 🟡 PART | ✅ PASS | 4194328/0 | 6029364/0 | 6947000/0 | egress 1.0 | bucketed as unknown |
| s10 | Raw IP socket (proto 253) egress | ❌ FAIL | ❌ FAIL | 4194304/0 | 4254224/0 | 0/0 | egress 0.0 | not detected |
| s11 | Short-lived processes | 🟡 PART | ❌ FAIL | 10486240/0 | 10871668/55332 | 4620330/32156 | egress 0.421 | bucketed as unknown |
| s12 | AF_PACKET raw-frame injection | 🟡 PART | ✅ PASS | 4194304/0 | 4278192/0 | 4005000/0 | egress 0.9271 | bucketed as unknown |
| s13 | io_uring data path | ✅ PASS | 🟡 PART | 25165848/0 | 26081628/36876 | 21813300/39806 | egress 0.8285 |  |
| s14 | sendfile() zero-copy upload | ✅ PASS | ✅ PASS | 33554456/0 | 34779376/78632 | 35109200/99800 | egress 1.0 |  |
| s15 | sendmmsg batched UDP | 🟡 PART | ✅ PASS | 25177624/0 | 25681204/0 | 25933000/0 | egress 1.0 | bucketed as unknown |
| s16 | Loopback-only transfer | ✅ PASS | ❌ FAIL | 24/25165824 | 24/25165824 | 27752/0 | ingress 0.0 |  |
| s17 | In-container (docker) egress | 🟡 PART | ✅ PASS | 25165848/0 | 26084644/37136 | 26332000/47132 | egress 1.0 | bucketed as unknown |
| s18 | Low-and-slow drip upload | ✅ PASS | ✅ PASS | 2097176/0 | 2173988/32352 | 2194670/41060 | egress 1.0 |  |
| s19 | Many small TCP connections | ✅ PASS | ❌ FAIL | 3933600/0 | 4093200/75100 | 1516550/34826 | egress 0.3667 |  |
| s20 | High-rate parallel burst | 🟡 PART | ❌ FAIL | 7865040/0 | 8157520/63160 | 1924000/22570 | egress 0.2336 | bucketed as unknown |
| s21 | io_uring download (recv) | ✅ PASS | 🟡 PART* | 24/25165824 | 130428/25205968 | 142088/19497500 | ingress 0.7732 |  |
| s22 | splice() zero-copy download | ✅ PASS | ✅ PASS | 24/33554432 | 141420/33608000 | 179552/35109100 | ingress 1.0442 |  |
| s23 | recvmmsg batched UDP (recv) | 🟡 PART | ✅ PASS | 24/25165824 | 52/25669152 | 0/25921000 | ingress 1.0 | bucketed as unknown |
| s24 | IPv6 UDP download | 🟡 PART | ✅ PASS | 24/25165824 | 72/26028672 | 0/26280000 | ingress 1.0 | bucketed as unknown |

Rows show the first trial's numbers; verdicts combine all trials. \* = trials disagreed.
