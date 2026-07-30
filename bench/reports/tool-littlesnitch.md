# Little Snitch: detailed results

- scored against: **application bytes**

- **control (separate from the s01 row):** det=PASS bw=PASS (reference recv=33554432, reported recv=33554432)

Rows show the first trial's numbers; verdicts combine all trials. \* = trials disagreed.

| # | Scenario | Det | BW | reference s/r | reported s/r | ratio | note |
|---|---|---|---|---|---|---|---|
| s01 | TCP bulk download (control) | ✅ PASS | ✅ PASS | -/33554432 | 24/33554432 | ingress 1.0 | WebSocket per-app stats |
| s02 | TCP bulk upload | ✅ PASS | ✅ PASS | 33554456/- | 33554456/0 | egress 1.0 | WebSocket per-app stats |
| s03 | TCP full-duplex up+down | ✅ PASS | ✅ PASS | 25165872/25165824 | 25165872/25165824 | egress 1.0 ingress 1.0 | WebSocket per-app stats |
| s04 | UDP bulk up+down | ✅ PASS | ✅ PASS | 25166448/25165824 | 25166448/25165824 | egress 1.0 ingress 1.0 | WebSocket per-app stats |
| s05 | ICMP echo flood w/ payload | 🟡 PART* | ❌ FAIL | 6342336/6468176 | 2924652/2923648 | egress 0.4611 ingress 0.452 | WebSocket per-app stats |
| s06 | UDP/443 bulk | ✅ PASS | ✅ PASS | 25166424/- | 25166424/0 | egress 1.0 | WebSocket per-app stats |
| s07 | IPv6 TCP transfer | ✅ PASS | ✅ PASS | -/25165824 | 24/25165824 | ingress 1.0 | WebSocket per-app stats |
| s08 | SCTP transfer | ✅ PASS | ✅ PASS | -/25165824 | 25590452/25590392 | ingress 1.0169 | WebSocket per-app stats |
| s09 | Small-packet UDP/53 flood | ✅ PASS | ❌ FAIL | 4194328/- | 1973592/0 | egress 0.4705 | WebSocket per-app stats |
| s10 | Raw IP socket (proto 253) egress | ❌ FAIL | ❌ FAIL | 4194304/- | 0/0 | egress 0.0 | no matching app row |
| s11 | Short-lived processes | ✅ PASS | ✅ PASS | 10486240/- | 10486240/0 | egress 1.0 | WebSocket per-app stats |
| s12 | AF_PACKET raw-frame injection | 🟡 PART | ❌ FAIL | 4194304/- | 0/0 | egress 0.0 | recorded under another application |
| s13 | io_uring data path | ✅ PASS | ❌ FAIL | 25165848/- | 10681640/0 | egress 0.4244 | WebSocket per-app stats |
| s14 | sendfile() zero-copy upload | ✅ PASS | ✅ PASS | 33554456/- | 33567864/0 | egress 1.0004 | WebSocket per-app stats |
| s15 | sendmmsg batched UDP | ✅ PASS | ✅ PASS | 25177624/- | 25177624/0 | egress 1.0 | WebSocket per-app stats |
| s16 | Loopback-only transfer | ❌ FAIL | ❌ FAIL | -/25165824 | 0/0 | ingress 0.0 | no matching app row |
| s17 | In-container (docker) egress | 🟡 PART | ❌ FAIL | 25165848/- | 0/0 | egress 0.0 | recorded under another application |
| s18 | Low-and-slow drip upload | ✅ PASS | ✅ PASS | 2097176/- | 2097176/0 | egress 1.0 | WebSocket per-app stats |
| s19 | Many small TCP connections | ✅ PASS | ✅ PASS* | 3933600/- | 3933600/0 | egress 1.0 | WebSocket per-app stats |
| s20 | High-rate parallel burst | ✅ PASS | ✅ PASS | 7865040/- | 7866128/0 | egress 1.0001 | WebSocket per-app stats |
| s21 | io_uring download (recv) | ✅ PASS | ❌ FAIL | -/25165824 | 24/12811752 | ingress 0.5091 | WebSocket per-app stats |
| s22 | splice() zero-copy download | ✅ PASS | ✅ PASS | -/33554432 | 24/33554432 | ingress 1.0 | WebSocket per-app stats |
| s23 | recvmmsg batched UDP (recv) | ✅ PASS | ✅ PASS | -/25165824 | 24/25165824 | ingress 1.0 | WebSocket per-app stats |
| s24 | IPv6 UDP download | ✅ PASS | ✅ PASS | -/25165824 | 24/25165824 | ingress 1.0 | WebSocket per-app stats |
