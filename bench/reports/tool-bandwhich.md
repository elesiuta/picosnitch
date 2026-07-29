# bandwhich: detailed results

- layer scored against: **wire** (wire bytes)

- **control (separate from the s01 row):** det=PASS bw=PASS (ref recv=33554432, reported recv=32304630)

| # | Scenario | Det | BW | ref app s/r | ref wire s/r | reported s/r | ratio | note |
|---|---|---|---|---|---|---|---|---|
| s01 | TCP bulk download (control) | ✅ PASS | ✅ PASS* | 24/33554432 | 52240/33608104 | 29917/30488710 | ingress 0.9068 |  |
| s02 | TCP bulk upload | ✅ PASS | 🟡 PART* | 33554456/0 | 34779428/42076 | 32931426/24989 | egress 0.938 |  |
| s03 | TCP full-duplex up+down | ✅ PASS | ✅ PASS* | 25165872/25165824 | 26135584/25234688 | 20504575/20504520 | egress 0.7768 |  |
| s04 | UDP bulk up+down | ✅ PASS | ✅ PASS | 25166448/25165824 | 25669832/25669152 | 24977947/24968060 | egress 0.9636 |  |
| s05 | ICMP echo flood w/ payload | ❌ FAIL | ❌ FAIL | 6342336/6468176 | 6468176/6468176 | 0/0 | egress 0.0 | not detected |
| s06 | UDP/443 bulk | ✅ PASS | 🟡 PART | 25166424/0 | 25669780/0 | 21249565/0 | egress 0.8198 |  |
| s07 | IPv6 TCP transfer | ✅ PASS | 🟡 PART* | 24/25165824 | 50504/25221632 | 22204/25262085 | ingress 1.0012 |  |
| s08 | SCTP transfer | ❌ FAIL | ❌ FAIL | 24/25165824 | 424472/25572252 | 0/0 | ingress 0.0 | not detected |
| s09 | Small-packet UDP/53 flood | ❌ FAIL | ❌ FAIL | 4194328/0 | 6029364/0 | 0/0 | egress 0.0 | not detected |
| s10 | Raw IP socket (proto 253) egress | ❌ FAIL | ❌ FAIL | 4194304/0 | 4254224/0 | 0/0 | egress 0.0 | not detected |
| s11 | Short-lived processes | 🟡 PART | 🟡 PART | 10486240/0 | 10871356/53876 | 9085380/32000 | egress 0.8278 | bucketed as <UNKNOWN> |
| s12 | AF_PACKET raw-frame injection | 🟡 PART | ✅ PASS* | 4194304/0 | 4278192/0 | 3343900/0 | egress 0.774 | bucketed as <UNKNOWN> |
| s13 | io_uring data path | 🟡 PART* | ❌ FAIL | 25165848/0 | 26084280/53568 | 16279760/26085 | egress 0.6183 |  |
| s14 | sendfile() zero-copy upload | ✅ PASS | ❌ FAIL | 33554456/0 | 34779428/36148 | 25744811/20162 | egress 0.7333 |  |
| s15 | sendmmsg batched UDP | ✅ PASS | 🟡 PART | 25177624/0 | 25681204/0 | 22257692/0 | egress 0.8583 |  |
| s16 | Loopback-only transfer | ✅ PASS | ❌ FAIL | 24/25165824 | 24/25165824 | 26175/0 | ingress 0.0 |  |
| s17 | In-container (docker) egress | 🟡 PART | ✅ PASS | 25165848/0 | 26084644/28712 | 25235388/17362 | egress 0.9584 | bucketed as <UNKNOWN> |
| s18 | Low-and-slow drip upload | ✅ PASS | ✅ PASS | 2097176/0 | 2173988/32092 | 2050569/18810 | egress 0.9343 |  |
| s19 | Many small TCP connections | ✅ PASS | ❌ FAIL | 3933600/0 | 4093200/74580 | 67165/740 | egress 0.0162 |  |
| s20 | High-rate parallel burst | 🟡 PART | ❌ FAIL | 7865040/0 | 8159848/55416 | 4443260/23680 | egress 0.5393 | bucketed as <UNKNOWN> |
| s21 | io_uring download (recv) | 🟡 PART | ❌ FAIL* | 24/25165824 | 114068/25205612 | 51645/14370400 | ingress 0.5699 | bucketed as <UNKNOWN> |
| s22 | splice() zero-copy download | ✅ PASS | ✅ PASS* | 24/33554432 | 106840/33608052 | 62852/32632967 | ingress 0.9706 |  |
| s23 | recvmmsg batched UDP (recv) | ✅ PASS | 🟡 PART* | 24/25165824 | 52/25669152 | 30/22223869 | ingress 0.8574 |  |
| s24 | IPv6 UDP download | ✅ PASS | 🟡 PART* | 24/25165824 | 72/26028672 | 30/23930365 | ingress 0.9106 |  |

Rows show the first trial's numbers; verdicts combine all trials. \* = trials disagreed.
