# Little Snitch — detailed results

- layer scored against: **socket** (app-layer bytes)

- **control (bulk TCP download smoke transfer, separate from the s01 row):** det=PASS bw=PASS (gt recv=33554432, reported recv=33554432)

| # | Scenario | Det | BW | GT app s/r | GT wire s/r | reported s/r | ratio | note |
|---|---|---|---|---|---|---|---|---|
| s01 | TCP bulk download (control) | ✅ PASS | ✅ PASS | 24/33554432 | 57804/33608104 | 24/33554432 | ingress 1.0 | web-socket per-app stats |
| s02 | TCP bulk upload | ✅ PASS | ✅ PASS | 33554456/0 | 34779428/51124 | 33554456/0 | egress 1.0 | web-socket per-app stats |
| s03 | TCP full-duplex up+down | ✅ PASS | ✅ PASS | 25165872/25165824 | 26133192/25240356 | 25165872/25165824 | egress 1.0 | web-socket per-app stats |
| s04 | UDP bulk up+down | ✅ PASS | ✅ PASS | 25166448/25165824 | 25669832/25669152 | 25166448/25165824 | egress 1.0 | web-socket per-app stats |
| s05 | ICMP echo flood w/ payload | ❌ FAIL⚡ | ❌ FAIL⚡ | 6342336/6468176 | 6468176/6468176 | 5757940/5757940 | egress 0.9079 | web-socket per-app stats |
| s06 | UDP/443 bulk | ✅ PASS | ✅ PASS | 25166424/0 | 25669780/0 | 25166424/0 | egress 1.0 | web-socket per-app stats |
| s07 | IPv6 TCP transfer | ✅ PASS | ✅ PASS | 24/25165824 | 51728/25221704 | 24/25165824 | ingress 1.0 | web-socket per-app stats |
| s08 | SCTP transfer | ✅ PASS | ✅ PASS | 24/25165824 | 424472/25572252 | 25590452/25590392 | ingress 1.0169 | web-socket per-app stats |
| s09 | Small-packet UDP/53 flood | ✅ PASS | ❌ FAIL | 4194328/0 | 6029364/0 | 2045528/0 | egress 0.4877 | web-socket per-app stats |
| s10 | Raw IP socket (proto 253) egress | ❌ FAIL | ❌ FAIL | 4194304/0 | 4254224/0 | 0/0 | egress 0.0 | no app row (attributed to a parent app) |
| s11 | Short-lived processes | ✅ PASS | ✅ PASS | 10486240/0 | 10871460/68488 | 10486240/0 | egress 1.0 | web-socket per-app stats |
| s12 | AF_PACKET raw-frame injection | ❌ FAIL | ❌ FAIL | 4194304/0 | 4278192/0 | 0/0 | egress 0.0 | no app row (attributed to a parent app) |
| s13 | io_uring data path | ✅ PASS | ❌ FAIL⚡ | 25165848/0 | 26084540/105828 | 9567904/0 | egress 0.3802 | web-socket per-app stats |
| s14 | sendfile() zero-copy upload | ✅ PASS | ✅ PASS | 33554456/0 | 34779272/41660 | 33554456/0 | egress 1.0 | web-socket per-app stats |
| s15 | sendmmsg batched UDP | ✅ PASS | ✅ PASS | 25177624/0 | 25681204/0 | 25177624/0 | egress 1.0 | web-socket per-app stats |
| s16 | Loopback-only transfer | ❌ FAIL | ❌ FAIL | 24/25165824 | 24/25165824 | 0/0 | ingress 0.0 | no app row (attributed to a parent app) |
| s17 | In-container (docker) egress | ❌ FAIL | ❌ FAIL | 25165848/0 | 26084644/39736 | 0/0 | egress 0.0 | no app row (attributed to a parent app) |
| s18 | Low-and-slow drip upload | ✅ PASS | ✅ PASS | 2097176/0 | 2173988/26736 | 2097176/0 | egress 1.0 | web-socket per-app stats |
| s19 | Many small TCP connections | ✅ PASS | ✅ PASS | 3933600/0 | 4093200/75152 | 3933600/0 | egress 1.0 | web-socket per-app stats |
| s20 | High-rate parallel burst | ✅ PASS | ✅ PASS | 7865040/0 | 8157520/55360 | 7865040/0 | egress 1.0 | web-socket per-app stats |
| s21 | io_uring download (recv) | ✅ PASS | ❌ FAIL | 24/25165824 | 176468/25205820 | 24/7916448 | ingress 0.3146 | web-socket per-app stats |
| s22 | splice() zero-copy download | ✅ PASS | ✅ PASS | 24/33554432 | 78916/33608052 | 24/33554432 | ingress 1.0 | web-socket per-app stats |
| s23 | recvmmsg batched UDP (recv) | ✅ PASS | ✅ PASS | 24/25165824 | 52/25669152 | 24/25165824 | ingress 1.0 | web-socket per-app stats |
| s24 | IPv6 UDP download | ✅ PASS | ✅ PASS | 24/25165824 | 72/26028672 | 24/25165824 | ingress 1.0 | web-socket per-app stats |

⚡/\* rows: trials disagreed; the table shows the first trial's numbers, while the verdict combines all trials (best of 5 for Sniffnet).
