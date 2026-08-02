# NetHogs: detailed results

- scored against: **wire bytes (L3 + Ethernet header per packet)**

- **control (separate from the s01 row):** det=PASS bw=PASS (reference recv=33554432, reported recv=35109100)

Rows show the first trial's numbers; verdicts combine all trials. \* = trials disagreed.

| # | Scenario | Det | BW | reference s/r | reported s/r | ratio | note |
|---|---|---|---|---|---|---|---|
| s01 | TCP bulk download (control) | ✅ PASS | ✅ PASS | -/33622486 | 54888/35109330 | ingress 1.0442 | named 54746/35109100, unknown 142/230 |
| s02 | TCP bulk upload | ✅ PASS | ✅ PASS | 35109226/- | 35109200/72872 | egress 1.0 |  |
| s03 | TCP full-duplex up+down | ✅ PASS | ✅ PASS | 26396326/25257250 | 26396316/26372168 | egress 1.0 ingress 1.0441 |  |
| s04 | UDP bulk up+down | 🟡 PART | ✅ PASS | 25921524/25920816 | 25921510/25920834 | egress 1.0 ingress 1.0 | named 0/0, unknown 25921510/25920834 |
| s05 | ICMP echo flood w/ payload | ❌ FAIL | ❌ FAIL | 6556264/6556264 | 0/0 | egress 0.0 ingress 0.0 |  |
| s06 | UDP/443 bulk | 🟡 PART | ✅ PASS | 25921458/- | 25922000/0 | egress 1.0 | named 0/0, unknown 25922000/0 |
| s07 | IPv6 TCP transfer | ✅ PASS | ✅ PASS | -/25232310 | 79840/26685200 | ingress 1.0576 |  |
| s08 | SCTP transfer | ❌ FAIL* | ❌ FAIL | -/25626278 | 0/0 | ingress 0.0 |  |
| s09 | Small-packet UDP/53 flood | 🟡 PART | ✅ PASS | 6946882/- | 6947000/0 | egress 1.0 | named 0/0, unknown 6947000/0 |
| s10 | Raw IP socket (proto 253) egress | ❌ FAIL | ❌ FAIL | 4296168/- | 0/0 | egress 0.0 |  |
| s11 | Short-lived processes | 🟡 PART | ❌ FAIL | 10974338/- | 4370460/32816 | egress 0.3982 | named 0/0, unknown 4370460/32816 |
| s12 | AF_PACKET raw-frame injection | 🟡 PART | ✅ PASS* | 4320136/- | 1972000/0 | egress 0.4565 | named 0/0, unknown 1972000/0 |
| s13 | io_uring data path | ✅ PASS | 🟡 PART | 26331482/- | 20949100/32018 | egress 0.7956 |  |
| s14 | sendfile() zero-copy upload | ✅ PASS | ✅ PASS | 35109160/- | 35109200/41192 | egress 1.0 |  |
| s15 | sendmmsg batched UDP | 🟡 PART | ✅ PASS | 25932994/- | 25933000/0 | egress 1.0 | named 0/0, unknown 25933000/0 |
| s16 | Loopback-only transfer | ✅ PASS | ⬜ N/A | -/- | 27752/0 |  |  |
| s17 | In-container (docker) egress | 🟡 PART | ✅ PASS | 26332010/- | 26332000/41522 | egress 1.0 | named 0/0, unknown 26332000/41522 |
| s18 | Low-and-slow drip upload | ✅ PASS | ✅ PASS | 2194666/- | 2194670/38024 | egress 1.0 |  |
| s19 | Many small TCP connections | ✅ PASS | ✅ PASS | 4136040/- | 4136550/95388 | egress 1.0001 | named 1516550/34892, unknown 2620000/60496 |
| s20 | High-rate parallel burst | 🟡 PART | ❌ FAIL | 8236398/- | 2087000/21514 | egress 0.2534 | named 0/0, unknown 2087000/21514 |
| s21 | io_uring download (recv) | ✅ PASS | ✅ PASS* | -/25216850 | 288188/23642200 | ingress 0.9376 |  |
| s22 | splice() zero-copy download | ✅ PASS | ✅ PASS | -/33622420 | 133418/35109100 | ingress 1.0442 |  |
| s23 | recvmmsg batched UDP (recv) | 🟡 PART | ✅ PASS | -/25920816 | 0/25921000 | ingress 1.0 | named 0/0, unknown 0/25921000 |
| s24 | IPv6 UDP download | 🟡 PART | ✅ PASS | -/26280336 | 0/26280000 | ingress 1.0 | named 0/0, unknown 0/26280000 |
