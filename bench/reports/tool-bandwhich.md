# bandwhich: detailed results

- scored against: **IP payload bytes (L3 minus the IP header per packet)**

- **control (separate from the s01 row):** det=PASS bw=PASS (reference recv=33554432, reported recv=33912846)

Rows show the first trial's numbers; verdicts combine all trials. \* = trials disagreed.

| # | Scenario | Det | BW | reference s/r | reported s/r | ratio | note |
|---|---|---|---|---|---|---|---|
| s01 | TCP bulk download (control) | ✅ PASS | ✅ PASS | -/33587432 | 29077/33798928 | ingress 1.0063 | named 26493/31761860, <UNKNOWN> 2584/2037068 |
| s02 | TCP bulk upload | ✅ PASS | ✅ PASS | 34308288/- | 34241215/24484 | egress 0.998 |  |
| s03 | TCP full-duplex up+down | ✅ PASS | ✅ PASS | 25799904/25214192 | 25531104/25486451 | egress 0.9896 ingress 1.0108 | named 24455932/24413351, <UNKNOWN> 1075172/1073100 |
| s04 | UDP bulk up+down | ✅ PASS | ✅ PASS | 25310272/25309632 | 24909546/24907899 | egress 0.9842 ingress 0.9841 | named 23306682/23300987, <UNKNOWN> 1602864/1606912 |
| s05 | ICMP echo flood w/ payload | ❌ FAIL | ❌ FAIL | 6342336/6342336 | 0/0 | egress 0.0 ingress 0.0 |  |
| s06 | UDP/443 bulk | ✅ PASS | ✅ PASS | 25310240/- | 25310232/0 | egress 1.0 | named 20187932/0, <UNKNOWN> 5122300/0 |
| s07 | IPv6 TCP transfer | ✅ PASS | ✅ PASS | -/25190632 | 22088/24712647 | ingress 0.981 | named 20092/20638535, <UNKNOWN> 1996/4074112 |
| s08 | SCTP transfer | ❌ FAIL | ❌ FAIL | -/25495072 | 0/0 | ingress 0.0 |  |
| s09 | Small-packet UDP/53 flood | ✅ PASS | ✅ PASS | 4718624/- | 4718620/0 | egress 1.0 | named 3331180/0, <UNKNOWN> 1387440/0 |
| s10 | Raw IP socket (proto 253) egress | ❌ FAIL | ❌ FAIL | 4194304/- | 0/0 | egress 0.0 |  |
| s11 | Short-lived processes | 🟡 PART | ✅ PASS* | 10723968/- | 9968480/36540 | egress 0.9296 | named 0/0, <UNKNOWN> 9968480/36540 |
| s12 | AF_PACKET raw-frame injection | 🟡 PART | 🟡 PART* | 4218272/- | 3763485/0 | egress 0.8922 | named 0/0, <UNKNOWN> 3763485/0 |
| s13 | io_uring data path | 🟡 PART | ❌ FAIL* | 25731072/- | 12031080/17255 | egress 0.4676 | named 0/0, <UNKNOWN> 12031080/17255 |
| s14 | sendfile() zero-copy upload | ✅ PASS | ✅ PASS* | 34308288/- | 32567849/41698 | egress 0.9493 | named 27765869/36963, <UNKNOWN> 4801980/4735 |
| s15 | sendmmsg batched UDP | ✅ PASS | ✅ PASS | 25321504/- | 24825884/0 | egress 0.9804 | named 22843420/0, <UNKNOWN> 1982464/0 |
| s16 | Loopback-only transfer | ✅ PASS | ⬜ N/A | -/- | 26939/0 |  | named 24639/0, <UNKNOWN> 2300/0 |
| s17 | In-container (docker) egress | 🟡 PART | ✅ PASS | 25731264/- | 25221987/22046 | egress 0.9802 | named 0/0, <UNKNOWN> 25221987/22046 |
| s18 | Low-and-slow drip upload | ✅ PASS | ✅ PASS | 2144448/- | 2117603/17478 | egress 0.9875 |  |
| s19 | Many small TCP connections | ✅ PASS | ✅ PASS | 4032000/- | 4032001/45505 | egress 1.0 | named 67165/710, <UNKNOWN> 3964836/44795 |
| s20 | High-rate parallel burst | 🟡 PART | ❌ FAIL | 8045472/- | 5739300/28040 | egress 0.7134 | named 0/0, <UNKNOWN> 5739300/28040 |
| s21 | io_uring download (recv) | 🟡 PART | ❌ FAIL* | -/25190696 | 109920/23014800 | ingress 0.9136 | named 0/0, <UNKNOWN> 109920/23014800 |
| s22 | splice() zero-copy download | ✅ PASS | ✅ PASS | -/33587752 | 101023/32673192 | ingress 0.9728 | named 98491/31828872, <UNKNOWN> 2532/844320 |
| s23 | recvmmsg batched UDP (recv) | ✅ PASS | ✅ PASS | -/25309632 | 30/25309628 | ingress 1.0 | named 30/20618748, <UNKNOWN> 0/4690880 |
| s24 | IPv6 UDP download | ✅ PASS | ✅ PASS | -/25309632 | 30/25072073 | ingress 0.9906 | named 30/24121853, <UNKNOWN> 0/950220 |
