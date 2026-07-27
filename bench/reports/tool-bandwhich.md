# bandwhich — detailed results

- layer scored against: **wire** (wire bytes)
- does bandwidth: True · does per-process attribution: True

- **control (bulk TCP download smoke transfer, separate from the s01 row):** det=PASS bw=PASS (gt recv=33554432, reported recv=32445346)

| # | Scenario | Det | BW | GT app s/r | GT wire s/r | reported s/r | ratio | note |
|---|---|---|---|---|---|---|---|---|
| s01 | TCP bulk download (control) | ✅ PASS | ✅ PASS⚡ | 24/33554432 | 56920/33608000 | 32636/31627845 | ingress 0.9407 |  |
| s02 | TCP bulk upload | ✅ PASS | 🟡 PART⚡ | 33554456/0 | 34779428/36408 | 29885695/19844 | egress 0.8512 |  |
| s03 | TCP full-duplex up+down | ✅ PASS | ✅ PASS⚡ | 25165872/25165824 | 26128148/25232244 | 24257020/24256965 | egress 0.9193 |  |
| s04 | UDP bulk up+down | ✅ PASS | ✅ PASS | 25166448/25165824 | 25669832/25669152 | 23936029/23931774 | egress 0.9234 |  |
| s05 | ICMP echo flood w/ payload | ❌ FAIL | ❌ FAIL | 6342336/6468176 | 6468176/6468176 | 0/0 | egress 0.0 | not detected |
| s06 | QUIC-style UDP:443 bulk | ✅ PASS | 🟡 PART | 25166424/0 | 25669780/0 | 23030685/0 | egress 0.8885 |  |
| s07 | IPv6 TCP transfer | ✅ PASS | 🟡 PART⚡ | 24/25165824 | 41792/25221704 | 16029/20973575 | ingress 0.8312 |  |
| s08 | SCTP transfer | ❌ FAIL | ❌ FAIL | 24/25165824 | 424472/25572252 | 0/0 | ingress 0.0 | not detected |
| s09 | DNS-style small UDP:53 flood | ❌ FAIL | ❌ FAIL | 4194328/0 | 6029364/0 | 0/0 | egress 0.0 | not detected |
| s10 | Raw IP socket (proto 253) egress | ❌ FAIL | ❌ FAIL | 4194304/0 | 4254224/0 | 0/0 | egress 0.0 | not detected |
| s11 | Short-lived processes | 🟡 PART | 🟡 PART | 10486240/0 | 10872344/58192 | 9708245/35580 | egress 0.8845 | bucketed as <UNKNOWN> |
| s12 | AF_PACKET raw-frame injection | 🟡 PART | ✅ PASS⚡ | 4194304/0 | 4278192/0 | 3445280/0 | egress 0.7975 | bucketed as <UNKNOWN> |
| s13 | io_uring data path | 🟡 PART⚡ | ❌ FAIL⚡ | 25165848/0 | 26083656/35264 | 14503820/21350 | egress 0.5508 | bucketed as <UNKNOWN> |
| s14 | sendfile() zero-copy upload | ✅ PASS | ❌ FAIL⚡ | 33554456/0 | 34779428/43012 | 27944995/22117 | egress 0.7959 |  |
| s15 | sendmmsg batched UDP | ✅ PASS | ✅ PASS | 25177624/0 | 25681204/0 | 25006108/0 | egress 0.9643 |  |
| s16 | Loopback-only transfer | ✅ PASS | ❌ FAIL | 24/25165824 | 24/25165824 | 25660/0 | ingress 0.0 |  |
| s17 | In-container (docker) egress | 🟡 PART | ✅ PASS | 25165848/0 | 26084644/31520 | 25315798/38297 | egress 0.9614 | bucketed as <UNKNOWN> |
| s18 | Low-and-slow drip upload | ✅ PASS | ✅ PASS | 2097176/0 | 2173988/36200 | 2050569/21252 | egress 0.9343 |  |
| s19 | Many small TCP connections | ✅ PASS | ❌ FAIL | 3933600/0 | 4093200/73800 | 67165/740 | egress 0.0162 |  |
| s20 | High-rate parallel burst | 🟡 PART | ❌ FAIL | 7865040/0 | 8158508/53644 | 4475600/25815 | egress 0.5433 | bucketed as <UNKNOWN> |
| s21 | io_uring download (recv) | 🟡 PART | 🟡 PART⚡ | 24/25165824 | 244328/25206236 | 104220/20060615 | ingress 0.7955 | bucketed as <UNKNOWN> |
| s22 | splice() zero-copy download | ✅ PASS | ✅ PASS⚡ | 24/33554432 | 99352/33608052 | 52444/29081540 | ingress 0.8649 |  |
| s23 | recvmmsg batched UDP (recv) | ✅ PASS | 🟡 PART⚡ | 24/25165824 | 52/25669152 | 30/20142845 | ingress 0.7771 |  |
| s24 | IPv6 UDP download | ✅ PASS | 🟡 PART | 24/25165824 | 72/26028672 | 30/21849340 | ingress 0.8314 |  |

⚡/\* rows: trials disagreed; the table shows the first trial's numbers, while the verdict combines all trials (best-of-5 for sniffnet).
