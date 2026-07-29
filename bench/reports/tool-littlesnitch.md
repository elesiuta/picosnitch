# Little Snitch: detailed results

- layer scored against: **socket** (app-layer bytes)

- **control (separate from the s01 row):** det=PASS bw=PASS (ref recv=33554432, reported recv=33554432)

| # | Scenario | Det | BW | ref app s/r | ref wire s/r | reported s/r | ratio | note |
|---|---|---|---|---|---|---|---|---|
| s01 | TCP bulk download (control) | ✅ PASS | ✅ PASS | 24/33554432 | 59208/33608052 | 24/33554432 | ingress 1.0 | WebSocket per-app stats |
| s02 | TCP bulk upload | ✅ PASS | ✅ PASS | 33554456/0 | 34779428/50708 | 33554456/0 | egress 1.0 | WebSocket per-app stats |
| s03 | TCP full-duplex up+down | ✅ PASS | ✅ PASS | 25165872/25165824 | 26124612/25235988 | 25165872/25165824 | egress 1.0 | WebSocket per-app stats |
| s04 | UDP bulk up+down | ✅ PASS | ✅ PASS | 25166448/25165824 | 25669832/25669152 | 25166448/25165824 | egress 1.0 | WebSocket per-app stats |
| s05 | ICMP echo flood w/ payload | ❌ FAIL* | ❌ FAIL | 6342336/6468176 | 6468176/6468176 | 2924652/2923648 | egress 0.4611 | WebSocket per-app stats |
| s06 | UDP/443 bulk | ✅ PASS | ✅ PASS | 25166424/0 | 25669780/0 | 25166424/0 | egress 1.0 | WebSocket per-app stats |
| s07 | IPv6 TCP transfer | ✅ PASS | ✅ PASS | 24/25165824 | 59792/25221632 | 24/25165824 | ingress 1.0 | WebSocket per-app stats |
| s08 | SCTP transfer | ✅ PASS | ✅ PASS | 24/25165824 | 424472/25572252 | 25590452/25590392 | ingress 1.0169 | WebSocket per-app stats |
| s09 | Small-packet UDP/53 flood | ✅ PASS | ❌ FAIL | 4194328/0 | 6029364/0 | 2025304/0 | egress 0.4829 | WebSocket per-app stats |
| s10 | Raw IP socket (proto 253) egress | ❌ FAIL | ❌ FAIL | 4194304/0 | 4254224/0 | 0/0 | egress 0.0 | no matching app row |
| s11 | Short-lived processes | ✅ PASS | ✅ PASS | 10486240/0 | 10872032/62872 | 10486240/0 | egress 1.0 | WebSocket per-app stats |
| s12 | AF_PACKET raw-frame injection | ❌ FAIL | ❌ FAIL | 4194304/0 | 4278192/0 | 0/0 | egress 0.0 | no matching app row |
| s13 | io_uring data path | ✅ PASS | ❌ FAIL | 25165848/0 | 26082244/40016 | 11004112/0 | egress 0.4373 | WebSocket per-app stats |
| s14 | sendfile() zero-copy upload | ✅ PASS | ✅ PASS | 33554456/0 | 34779324/46652 | 33554456/0 | egress 1.0 | WebSocket per-app stats |
| s15 | sendmmsg batched UDP | ✅ PASS | ✅ PASS | 25177624/0 | 25681204/0 | 25177624/0 | egress 1.0 | WebSocket per-app stats |
| s16 | Loopback-only transfer | ❌ FAIL | ❌ FAIL | 24/25165824 | 24/25165824 | 0/0 | ingress 0.0 | no matching app row |
| s17 | In-container (docker) egress | ❌ FAIL | ❌ FAIL | 25165848/0 | 26084644/36512 | 0/0 | egress 0.0 | no matching app row |
| s18 | Low-and-slow drip upload | ✅ PASS | ✅ PASS | 2097176/0 | 2173988/35108 | 2097176/0 | egress 1.0 | WebSocket per-app stats |
| s19 | Many small TCP connections | ✅ PASS | ✅ PASS | 3933600/0 | 4093200/75100 | 3933600/0 | egress 1.0 | WebSocket per-app stats |
| s20 | High-rate parallel burst | ✅ PASS | ✅ PASS | 7865040/0 | 8158764/63172 | 7866128/0 | egress 1.0001 | WebSocket per-app stats |
| s21 | io_uring download (recv) | ✅ PASS | ❌ FAIL* | 24/25165824 | 148752/25202908 | 24/8746696 | ingress 0.3476 | WebSocket per-app stats |
| s22 | splice() zero-copy download | ✅ PASS | ✅ PASS | 24/33554432 | 118696/33608052 | 24/33554432 | ingress 1.0 | WebSocket per-app stats |
| s23 | recvmmsg batched UDP (recv) | ✅ PASS | ✅ PASS | 24/25165824 | 52/25669152 | 24/25165824 | ingress 1.0 | WebSocket per-app stats |
| s24 | IPv6 UDP download | ✅ PASS | ✅ PASS | 24/25165824 | 72/26028672 | 24/25165824 | ingress 1.0 | WebSocket per-app stats |

Rows show the first trial's numbers; verdicts combine all trials. \* = trials disagreed.
