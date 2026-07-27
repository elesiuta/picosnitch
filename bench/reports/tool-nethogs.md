# nethogs — detailed results

- layer scored against: **wire** (wire bytes)
- does bandwidth: True · does per-process attribution: True

- **control (bulk TCP download smoke transfer, separate from the s01 row):** det=PASS bw=PASS (gt recv=33554432, reported recv=35109100)

| # | Scenario | Det | BW | GT app s/r | GT wire s/r | reported s/r | ratio | note |
|---|---|---|---|---|---|---|---|---|
| s01 | TCP bulk download (control) | ✅ PASS | ✅ PASS | 24/33554432 | 93060/33608000 | 118172/35109100 | ingress 1.0442 |  |
| s02 | TCP bulk upload | ✅ PASS | ✅ PASS | 33554456/0 | 34779428/48888 | 35109200/62048 | egress 1.0 |  |
| s03 | TCP full-duplex up+down | ✅ PASS | ✅ PASS | 25165872/25165824 | 26148636/25240044 | 26332000/26331900 | egress 0.9969 |  |
| s04 | UDP bulk up+down | 🟡 PART | ✅ PASS | 25166448/25165824 | 25669832/25669152 | 25921500/25920800 | egress 1.0 | bucketed as unknown |
| s05 | ICMP echo flood w/ payload | ❌ FAIL⚡ | ❌ FAIL | 6342336/6468176 | 6468176/6468176 | 0/0 | egress 0.0 | not detected |
| s06 | QUIC-style UDP:443 bulk | 🟡 PART | ✅ PASS | 25166424/0 | 25669780/0 | 25921000/0 | egress 1.0 | bucketed as unknown |
| s07 | IPv6 TCP transfer | ✅ PASS | ✅ PASS | 24/25165824 | 60080/25221560 | 71842/26685200 | ingress 1.0576 |  |
| s08 | SCTP transfer | ❌ FAIL | ❌ FAIL | 24/25165824 | 424472/25572252 | 0/0 | ingress 0.0 | not detected |
| s09 | DNS-style small UDP:53 flood | 🟡 PART | ✅ PASS | 4194328/0 | 6029364/0 | 6947000/0 | egress 1.0 | bucketed as unknown |
| s10 | Raw IP socket (proto 253) egress | ❌ FAIL | ❌ FAIL | 4194304/0 | 4254224/0 | 0/0 | egress 0.0 | not detected |
| s11 | Short-lived processes | 🟡 PART | ❌ FAIL | 10486240/0 | 10871876/58712 | 4080851/30358 | egress 0.3718 | bucketed as unknown |
| s12 | AF_PACKET raw-frame injection | 🟡 PART | ✅ PASS | 4194304/0 | 4278192/0 | 4174000/0 | egress 0.9662 | bucketed as unknown |
| s13 | io_uring data path | ✅ PASS | 🟡 PART⚡ | 25165848/0 | 26084072/37552 | 22043500/39146 | egress 0.8372 |  |
| s14 | sendfile() zero-copy upload | ✅ PASS | ✅ PASS | 33554456/0 | 34779376/39528 | 35109200/50168 | egress 1.0 |  |
| s15 | sendmmsg batched UDP | 🟡 PART | ✅ PASS | 25177624/0 | 25681204/0 | 25933000/0 | egress 1.0 | bucketed as unknown |
| s16 | Loopback-only transfer | ✅ PASS | ❌ FAIL | 24/25165824 | 24/25165824 | 27752/0 | ingress 0.0 |  |
| s17 | In-container (docker) egress | 🟡 PART | ✅ PASS | 25165848/0 | 26084644/33080 | 26332100/41984 | egress 1.0 | bucketed as unknown |
| s18 | Low-and-slow drip upload | ✅ PASS | ✅ PASS | 2097176/0 | 2173988/29024 | 2194670/36836 | egress 1.0 |  |
| s19 | Many small TCP connections | ✅ PASS | ❌ FAIL | 3933600/0 | 4093200/75048 | 1516550/34694 | egress 0.3667 |  |
| s20 | High-rate parallel burst | 🟡 PART | ❌ FAIL | 7865040/0 | 8157468/51304 | 1944000/14526 | egress 0.236 | bucketed as unknown |
| s21 | io_uring download (recv) | ✅ PASS⚡ | ✅ PASS⚡ | 24/25165824 | 142928/25205976 | 158696/20519700 | ingress 0.8137 |  |
| s22 | splice() zero-copy download | ✅ PASS | ✅ PASS | 24/33554432 | 119944/33608000 | 152294/35109100 | ingress 1.0442 |  |
| s23 | recvmmsg batched UDP (recv) | 🟡 PART | ✅ PASS | 24/25165824 | 52/25669152 | 0/25921000 | ingress 1.0 | bucketed as unknown |
| s24 | IPv6 UDP download | 🟡 PART | ✅ PASS | 24/25165824 | 72/26028672 | 0/26280000 | ingress 1.0 | bucketed as unknown |

⚡/\* rows: trials disagreed; the table shows the first trial's numbers, while the verdict combines all trials (best-of-5 for sniffnet).
