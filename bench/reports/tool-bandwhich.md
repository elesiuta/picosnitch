# bandwhich — detailed results

- layer scored against: **wire** (wire bytes)

- **control (bulk TCP download smoke transfer, separate from the s01 row):** det=PASS bw=PASS (gt recv=33554432, reported recv=32234274)

| # | Scenario | Det | BW | GT app s/r | GT wire s/r | reported s/r | ratio | note |
|---|---|---|---|---|---|---|---|---|
| s01 | TCP bulk download (control) | ✅ PASS | ✅ PASS⚡ | 24/33554432 | 66852/33608052 | 38330/30421700 | ingress 0.9048 |  |
| s02 | TCP bulk upload | ✅ PASS | 🟡 PART⚡ | 33554456/0 | 34779428/38540 | 32968062/22885 | egress 0.939 |  |
| s03 | TCP full-duplex up+down | ✅ PASS | ✅ PASS⚡ | 25165872/25165824 | 26138028/25229956 | 23854975/23854920 | egress 0.9036 |  |
| s04 | UDP bulk up+down | ✅ PASS | 🟡 PART⚡ | 25166448/25165824 | 25669832/25669152 | 23341853/23336187 | egress 0.9005 |  |
| s05 | ICMP echo flood w/ payload | ❌ FAIL | ❌ FAIL | 6342336/6468176 | 6468176/6468176 | 0/0 | egress 0.0 | not detected |
| s06 | UDP/443 bulk | ✅ PASS | 🟡 PART⚡ | 25166424/0 | 25669780/0 | 20330140/0 | egress 0.7843 |  |
| s07 | IPv6 TCP transfer | ✅ PASS | 🟡 PART⚡ | 24/25165824 | 53168/25221560 | 21116/21911685 | ingress 0.8684 |  |
| s08 | SCTP transfer | ❌ FAIL | ❌ FAIL | 24/25165824 | 424472/25572252 | 0/0 | ingress 0.0 | not detected |
| s09 | Small-packet UDP/53 flood | ❌ FAIL | ❌ FAIL | 4194328/0 | 6029364/0 | 0/0 | egress 0.0 | not detected |
| s10 | Raw IP socket (proto 253) egress | ❌ FAIL | ❌ FAIL | 4194304/0 | 4254224/0 | 0/0 | egress 0.0 | not detected |
| s11 | Short-lived processes | 🟡 PART | 🟡 PART | 10486240/0 | 10871044/46284 | 9044700/27550 | egress 0.8241 | bucketed as <UNKNOWN> |
| s12 | AF_PACKET raw-frame injection | 🟡 PART | ✅ PASS⚡ | 4194304/0 | 4278192/0 | 3242525/0 | egress 0.7506 | bucketed as <UNKNOWN> |
| s13 | io_uring data path | 🟡 PART | ❌ FAIL | 25165848/0 | 26083708/36876 | 14867500/22375 | egress 0.5646 | bucketed as <UNKNOWN> |
| s14 | sendfile() zero-copy upload | ✅ PASS | ❌ FAIL⚡ | 33554456/0 | 34779428/44624 | 29127525/24964 | egress 0.8296 |  |
| s15 | sendmmsg batched UDP | ✅ PASS | 🟡 PART⚡ | 25177624/0 | 25681204/0 | 22347804/0 | egress 0.8618 |  |
| s16 | Loopback-only transfer | ✅ PASS | ❌ FAIL | 24/25165824 | 24/25165824 | 24700/0 | ingress 0.0 |  |
| s17 | In-container (docker) egress | 🟡 PART | ✅ PASS | 25165848/0 | 26084644/40568 | 25020963/48908 | egress 0.9502 | bucketed as <UNKNOWN> |
| s18 | Low-and-slow drip upload | ✅ PASS | ✅ PASS | 2097176/0 | 2173988/28764 | 2050569/16793 | egress 0.9343 |  |
| s19 | Many small TCP connections | ✅ PASS | ❌ FAIL | 3933600/0 | 4093200/74372 | 67165/740 | egress 0.0162 |  |
| s20 | High-rate parallel burst | 🟡 PART | ❌ FAIL | 7865040/0 | 8157676/50784 | 5429920/26910 | egress 0.6593 | bucketed as <UNKNOWN> |
| s21 | io_uring download (recv) | 🟡 PART | ❌ FAIL⚡ | 24/25165824 | 177196/25206184 | 90495/22542980 | ingress 0.894 | bucketed as <UNKNOWN> |
| s22 | splice() zero-copy download | ✅ PASS | ✅ PASS⚡ | 24/33554432 | 94464/33608000 | 55748/32766982 | ingress 0.9746 |  |
| s23 | recvmmsg batched UDP (recv) | ✅ PASS | ✅ PASS⚡ | 24/25165824 | 52/25669152 | 30/21359356 | ingress 0.824 |  |
| s24 | IPv6 UDP download | ✅ PASS | 🟡 PART⚡ | 24/25165824 | 72/26028672 | 30/23423485 | ingress 0.8913 |  |

⚡/\* rows: trials disagreed; the table shows the first trial's numbers, while the verdict combines all trials (best of 5 for Sniffnet).
