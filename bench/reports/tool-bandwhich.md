# bandwhich: detailed results

- scored against: **IP payload bytes (L3 minus the IP header per packet)**

- **control (separate from the s01 row):** det=PASS bw=PASS (reference recv=33554432, reported recv=33896098)

Rows show the first trial's numbers; verdicts combine all trials. \* = trials disagreed.

| # | Scenario | Det | BW | reference s/r | reported s/r | ratio | note |
|---|---|---|---|---|---|---|---|
| s01 | TCP bulk download (control) | ✅ PASS | ✅ PASS | -/33587400 | 29928/33798928 | ingress 1.0063 | named 28700/31761860, <UNKNOWN> 1228/2037068 |
| s02 | TCP bulk upload | ✅ PASS | ✅ PASS | 34308288/- | 34241210/21093 | egress 0.998 |  |
| s03 | TCP full-duplex up+down | ✅ PASS | ✅ PASS | 25757408/25205296 | 25489024/25477620 | egress 0.9896 ingress 1.0108 | named 24415516/24404904, <UNKNOWN> 1073508/1072716 |
| s04 | UDP bulk up+down | ✅ PASS | ✅ PASS | 25310272/25309632 | 25152286/25150076 | egress 0.9938 ingress 0.9937 | named 24520378/24511868, <UNKNOWN> 631908/638208 |
| s05 | ICMP echo flood w/ payload | ❌ FAIL | ❌ FAIL | 6342336/6342336 | 0/0 | egress 0.0 ingress 0.0 |  |
| s06 | UDP/443 bulk | ✅ PASS | ✅ PASS | 25310240/- | 25150847/0 | egress 0.9937 | named 24513307/0, <UNKNOWN> 637540/0 |
| s07 | IPv6 TCP transfer | ✅ PASS | ✅ PASS | -/25190600 | 18394/24471408 | ingress 0.9714 | named 18166/24189957, <UNKNOWN> 228/281451 |
| s08 | SCTP transfer | ❌ FAIL | ❌ FAIL | -/25495072 | 0/0 | ingress 0.0 |  |
| s09 | Small-packet UDP/53 flood | ✅ PASS | ✅ PASS | 4718624/- | 4718619/0 | egress 1.0 | named 3947214/0, <UNKNOWN> 771405/0 |
| s10 | Raw IP socket (proto 253) egress | ❌ FAIL | ❌ FAIL | 4194304/- | 0/0 | egress 0.0 |  |
| s11 | Short-lived processes | 🟡 PART | 🟡 PART* | 10723200/- | 9922485/33980 | egress 0.9253 | named 0/0, <UNKNOWN> 9922485/33980 |
| s12 | AF_PACKET raw-frame injection | 🟡 PART | 🟡 PART* | 4218272/- | 3601565/0 | egress 0.8538 | named 0/0, <UNKNOWN> 3601565/0 |
| s13 | io_uring data path | 🟡 PART | ❌ FAIL* | 25731200/- | 18423620/43590 | egress 0.716 | named 0/0, <UNKNOWN> 18423620/43590 |
| s14 | sendfile() zero-copy upload | ✅ PASS | ✅ PASS* | 34308288/- | 32999394/26880 | egress 0.9618 | named 29934214/24900, <UNKNOWN> 3065180/1980 |
| s15 | sendmmsg batched UDP | ✅ PASS | ✅ PASS | 25321504/- | 25159296/0 | egress 0.9936 | named 24510492/0, <UNKNOWN> 648804/0 |
| s16 | Loopback-only transfer | ✅ PASS | ⬜ N/A | -/- | 26940/0 |  | named 25280/0, <UNKNOWN> 1660/0 |
| s17 | In-container (docker) egress | 🟡 PART | ✅ PASS | 25731264/- | 25490019/36171 | egress 0.9906 | named 0/0, <UNKNOWN> 25490019/36171 |
| s18 | Low-and-slow drip upload | ✅ PASS | ✅ PASS | 2144448/- | 2117603/16909 | egress 0.9875 |  |
| s19 | Many small TCP connections | ✅ PASS | ✅ PASS | 4032000/- | 4045409/46143 | egress 1.0033 | named 67165/740, <UNKNOWN> 3978244/45403 |
| s20 | High-rate parallel burst | 🟡 PART | ❌ FAIL | 8045632/- | 5375240/28165 | egress 0.6681 | named 0/0, <UNKNOWN> 5375240/28165 |
| s21 | io_uring download (recv) | 🟡 PART | ❌ FAIL* | -/25192872 | 33280/12670920 | ingress 0.503 | named 0/0, <UNKNOWN> 33280/12670920 |
| s22 | splice() zero-copy download | ✅ PASS | ✅ PASS | -/33587400 | 54536/33410282 | ingress 0.9947 | named 49340/29818630, <UNKNOWN> 5196/3591652 |
| s23 | recvmmsg batched UDP (recv) | ✅ PASS | ✅ PASS | -/25309632 | 30/25309628 | ingress 1.0 | named 30/24171133, <UNKNOWN> 0/1138495 |
| s24 | IPv6 UDP download | ✅ PASS | ✅ PASS | -/25309632 | 30/25025610 | ingress 0.9888 | named 30/23889534, <UNKNOWN> 0/1136076 |
