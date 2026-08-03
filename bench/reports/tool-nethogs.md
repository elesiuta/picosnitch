# NetHogs: detailed results

- scored against: **wire bytes (L3 + Ethernet header per packet)**

- **control (separate from the s01 row):** det=PASS bw=PASS (reference recv=33554432, reported recv=35109100)

Rows show the first trial's numbers; verdicts combine all trials. \* = trials disagreed.

| # | Scenario | Det | BW | reference s/r | reported s/r | ratio | note |
|---|---|---|---|---|---|---|---|
| s01 | TCP bulk download (control) | ✅ PASS | ✅ PASS | -/33622490 | 70652/35109100 | ingress 1.0442 |  |
| s02 | TCP bulk upload | ✅ PASS | ✅ PASS | 35109226/- | 35109200/47330 | egress 1.0 |  |
| s03 | TCP full-duplex up+down | ✅ PASS | ✅ PASS | 26389726/25254478 | 26389716/26369462 | egress 1.0 ingress 1.0441 |  |
| s04 | UDP bulk up+down | 🟡 PART | ✅ PASS | 25921524/25920816 | 25921500/25920800 | egress 1.0 ingress 1.0 | named 0/0, unknown 25921500/25920800 |
| s05 | ICMP echo flood w/ payload | ❌ FAIL | ❌ FAIL | 6556264/6556264 | 0/0 | egress 0.0 ingress 0.0 |  |
| s06 | UDP/443 bulk | 🟡 PART | ✅ PASS | 25921458/- | 25921000/0 | egress 1.0 | named 0/0, unknown 25921000/0 |
| s07 | IPv6 TCP transfer | ✅ PASS | ✅ PASS | -/25232396 | 55244/26685200 | ingress 1.0576 |  |
| s08 | SCTP transfer | ❌ FAIL | ❌ FAIL | -/25626278 | 0/0 | ingress 0.0 |  |
| s09 | Small-packet UDP/53 flood | 🟡 PART | ✅ PASS | 6946882/- | 6947000/0 | egress 1.0 | named 0/0, unknown 6947000/0 |
| s10 | Raw IP socket (proto 253) egress | ❌ FAIL | ❌ FAIL | 4296168/- | 0/0 | egress 0.0 |  |
| s11 | Short-lived processes | 🟡 PART | ❌ FAIL | 10974470/- | 4863980/35200 | egress 0.4432 | named 0/0, unknown 4863980/35200 |
| s12 | AF_PACKET raw-frame injection | 🟡 PART | ✅ PASS* | 4320136/- | 1856000/0 | egress 0.4296 | named 0/0, unknown 1856000/0 |
| s13 | io_uring data path | ✅ PASS | 🟡 PART | 26331746/- | 20536400/33140 | egress 0.7799 |  |
| s14 | sendfile() zero-copy upload | ✅ PASS | ✅ PASS | 35109226/- | 35109200/44030 | egress 1.0 |  |
| s15 | sendmmsg batched UDP | 🟡 PART | ✅ PASS | 25932994/- | 25933000/0 | egress 1.0 | named 0/0, unknown 25933000/0 |
| s16 | Loopback-only transfer | ✅ PASS | ⬜ N/A | -/- | 27752/0 |  |  |
| s17 | In-container (docker) egress | 🟡 PART | ✅ PASS | 26332010/- | 26332000/43766 | egress 1.0 | named 0/0, unknown 26332000/43766 |
| s18 | Low-and-slow drip upload | ✅ PASS | ✅ PASS | 2194666/- | 2194670/39014 | egress 1.0 |  |
| s19 | Many small TCP connections | ✅ PASS | ✅ PASS | 4136040/- | 4135550/95388 | egress 0.9999 | named 1516550/34958, unknown 2619000/60430 |
| s20 | High-rate parallel burst | 🟡 PART | ❌ FAIL | 8236002/- | 2175000/21414 | egress 0.2641 | named 0/0, unknown 2175000/21414 |
| s21 | io_uring download (recv) | ✅ PASS | 🟡 PART* | -/25216718 | 154076/20590200 | ingress 0.8165 |  |
| s22 | splice() zero-copy download | ✅ PASS | ✅ PASS | -/33622420 | 242384/35109100 | ingress 1.0442 |  |
| s23 | recvmmsg batched UDP (recv) | 🟡 PART | ✅ PASS | -/25920816 | 0/25921000 | ingress 1.0 | named 0/0, unknown 0/25921000 |
| s24 | IPv6 UDP download | 🟡 PART | ✅ PASS | -/26280336 | 0/26281000 | ingress 1.0 | named 0/0, unknown 0/26281000 |
