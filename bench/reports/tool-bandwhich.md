# bandwhich: detailed results

- scored against: **IP payload bytes (L3 minus the IP header per packet)**

- **control (separate from the s01 row):** det=PASS bw=PASS (reference recv=33554432, reported recv=32234274)

Rows show the first trial's numbers; verdicts combine all trials. \* = trials disagreed.

| # | Scenario | Det | BW | reference s/r | reported s/r | ratio | note |
|---|---|---|---|---|---|---|---|
| s01 | TCP bulk download (control) | ✅ PASS | ✅ PASS* | -/33587432 | 37565/30488710 | ingress 0.9077 | named 37565/30488710, <UNKNOWN> 2975/3819485 |
| s02 | TCP bulk upload | ✅ PASS | 🟡 PART* | 34308288/- | 28947580/23685 | egress 0.8437 | named 28947580/23685, <UNKNOWN> 5360860/4861 |
| s03 | TCP full-duplex up+down | ✅ PASS | ✅ PASS* | 25785344/25210096 | 25708539/20322571 | egress 0.997 ingress 0.8061 | named 25708539/20322571, <UNKNOWN> 76799/5427775 |
| s04 | UDP bulk up+down | ✅ PASS | 🟡 PART | 25310272/25309632 | 21500218/21494525 | egress 0.8495 ingress 0.8493 | named 21500218/21494525, <UNKNOWN> 3810045/3815100 |
| s05 | ICMP echo flood w/ payload | ❌ FAIL | ❌ FAIL | 6342336/6342336 | 0/0 | egress 0.0 ingress 0.0 |  |
| s06 | UDP/443 bulk | ✅ PASS | ✅ PASS* | 25310240/- | 23565725/0 | egress 0.9311 | named 23565725/0, <UNKNOWN> 1744510/0 |
| s07 | IPv6 TCP transfer | ✅ PASS | ✅ PASS* | -/25190632 | 22428/24927045 | ingress 0.9895 | named 22428/24927045, <UNKNOWN> 512/643300 |
| s08 | SCTP transfer | ❌ FAIL | ❌ FAIL | -/25495072 | 0/0 | ingress 0.0 |  |
| s09 | Small-packet UDP/53 flood | ✅ PASS | ❌ FAIL* | 4718624/- | 3370565/0 | egress 0.7143 | named 3370565/0, <UNKNOWN> 1348055/0 |
| s10 | Raw IP socket (proto 253) egress | ❌ FAIL | ❌ FAIL | 4194304/- | 0/0 | egress 0.0 |  |
| s11 | Short-lived processes | 🟡 PART | 🟡 PART* | 10724032/- | 9460205/36700 | egress 0.8822 | named 0/0, <UNKNOWN> 9460205/36700 |
| s12 | AF_PACKET raw-frame injection | 🟡 PART | ✅ PASS* | 4218272/- | 2372380/0 | egress 0.5624 | named 0/0, <UNKNOWN> 2372380/0 |
| s13 | io_uring data path | 🟡 PART | ❌ FAIL* | 25730976/- | 19564725/25735 | egress 0.7604 | named 0/0, <UNKNOWN> 19564725/25735 |
| s14 | sendfile() zero-copy upload | ✅ PASS | 🟡 PART* | 34308288/- | 26974790/17410 | egress 0.7862 | named 26974790/17410, <UNKNOWN> 1447750/990 |
| s15 | sendmmsg batched UDP | ✅ PASS | ✅ PASS* | 25321504/- | 24465436/0 | egress 0.9662 | named 24465436/0, <UNKNOWN> 856060/0 |
| s16 | Loopback-only transfer | ✅ PASS | ⬜ N/A | -/- | 24125/0 |  | named 24125/0, <UNKNOWN> 74904/0 |
| s17 | In-container (docker) egress | 🟡 PART | ✅ PASS | 25731264/- | 24980758/43455 | egress 0.9708 | named 0/0, <UNKNOWN> 24980758/43455 |
| s18 | Low-and-slow drip upload | ✅ PASS | ✅ PASS | 2144448/- | 2063991/19424 | egress 0.9625 | named 2063991/19424, <UNKNOWN> 120639/204 |
| s19 | Many small TCP connections | ✅ PASS | ❌ FAIL | 4032000/- | 67165/710 | egress 0.0167 | named 67165/710, <UNKNOWN> 3978244/45257 |
| s20 | High-rate parallel burst | 🟡 PART | ❌ FAIL | 8067864/- | 4620200/28640 | egress 0.5727 | named 0/0, <UNKNOWN> 4620200/28640 |
| s21 | io_uring download (recv) | 🟡 PART* | ❌ FAIL | -/25190600 | 36700/12571245 | ingress 0.499 | named 0/0, <UNKNOWN> 36700/12571245 |
| s22 | splice() zero-copy download | ✅ PASS | 🟡 PART* | -/33587432 | 56091/30086660 | ingress 0.8958 | named 56091/30086660, <UNKNOWN> 6750/4221535 |
| s23 | recvmmsg batched UDP (recv) | ✅ PASS | ✅ PASS* | -/25309632 | 30/23758587 | ingress 0.9387 | named 30/23758587, <UNKNOWN> 275/1738668 |
| s24 | IPv6 UDP download | ✅ PASS | 🟡 PART* | -/25309632 | 30/20031614 | ingress 0.7915 | named 30/20031614, <UNKNOWN> 0/5278015 |
