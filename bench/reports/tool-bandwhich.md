# bandwhich: detailed results

- scored against: **IP payload bytes (L3 minus the IP header per packet)**

- **control (separate from the s01 row):** det=PASS bw=PASS (reference recv=33554432, reported recv=33896433)

Rows show the first trial's numbers; verdicts combine all trials. \* = trials disagreed.

| # | Scenario | Det | BW | reference s/r | reported s/r | ratio | note |
|---|---|---|---|---|---|---|---|
| s01 | TCP bulk download (control) | ✅ PASS | ✅ PASS | -/33587400 | 816160/33785917 | ingress 1.0059 | named 35835/31694855, <UNKNOWN> 780325/2091062 |
| s02 | TCP bulk upload | ✅ PASS | ✅ PASS | 34308288/- | 33854678/1869088 | egress 0.9868 | named 32029950/18660, <UNKNOWN> 1824728/1850428 |
| s03 | TCP full-duplex up+down | ✅ PASS | ✅ PASS | 25750880/25206736 | 25576044/24849238 | egress 0.9932 ingress 0.9858 | named 21258233/21255082, <UNKNOWN> 4317811/3594156 |
| s04 | UDP bulk up+down | ✅ PASS | ✅ PASS | 25310272/25309632 | 25241247/25239549 | egress 0.9973 ingress 0.9972 | named 23488315/23484029, <UNKNOWN> 1752932/1755520 |
| s05 | ICMP echo flood w/ payload | ❌ FAIL* | ❌ FAIL | 6342336/6342336 | 170931/171942 | egress 0.027 ingress 0.0271 | named 0/0, <UNKNOWN> 170931/171942 |
| s06 | UDP/443 bulk | ✅ PASS | ✅ PASS | 25310240/- | 24892621/0 | egress 0.9835 | named 23222173/0, <UNKNOWN> 1670448/0 |
| s07 | IPv6 TCP transfer | ✅ PASS | ✅ PASS | -/25190632 | 516841/25369656 | ingress 1.0071 | named 20733/23921925, <UNKNOWN> 496108/1447731 |
| s08 | SCTP transfer | ❌ FAIL* | ❌ FAIL | -/25495072 | 370/509272 | ingress 0.02 | named 0/0, <UNKNOWN> 370/509272 |
| s09 | Small-packet UDP/53 flood | ✅ PASS | ✅ PASS | 4718624/- | 4718707/192 | egress 1.0 | named 3237725/0, <UNKNOWN> 1480982/192 |
| s10 | Raw IP socket (proto 253) egress | ❌ FAIL* | ❌ FAIL | 4194304/- | 323366/0 | egress 0.0771 | named 0/0, <UNKNOWN> 323366/0 |
| s11 | Short-lived processes | 🟡 PART | ✅ PASS* | 10723072/- | 9470790/32510 | egress 0.8832 | named 0/0, <UNKNOWN> 9470790/32510 |
| s12 | AF_PACKET raw-frame injection | 🟡 PART | ✅ PASS* | 4218272/- | 4218270/0 | egress 1.0 | named 0/0, <UNKNOWN> 4218270/0 |
| s13 | io_uring data path | 🟡 PART | ❌ FAIL* | 25730976/- | 15229080/16470 | egress 0.5919 | named 0/0, <UNKNOWN> 15229080/16470 |
| s14 | sendfile() zero-copy upload | ✅ PASS | 🟡 PART* | 34308192/- | 33288745/26659 | egress 0.9703 | named 32643915/26149, <UNKNOWN> 644830/510 |
| s15 | sendmmsg batched UDP | ✅ PASS | ✅ PASS | 25321504/- | 24609612/0 | egress 0.9719 | named 21762076/0, <UNKNOWN> 2847536/0 |
| s16 | Loopback-only transfer | ✅ PASS | ⬜ N/A | -/- | 819925/0 |  | named 22780/0, <UNKNOWN> 797145/0 |
| s17 | In-container (docker) egress | 🟡 PART | ✅ PASS | 25731264/- | 25235388/36864 | egress 0.9807 | named 0/0, <UNKNOWN> 25235388/36864 |
| s18 | Low-and-slow drip upload | ✅ PASS | ✅ PASS* | 2144448/- | 2680622/16672 | egress 1.25 | named 1983575/15553, <UNKNOWN> 697047/1119 |
| s19 | Many small TCP connections | ✅ PASS | ✅ PASS | 4032000/- | 4058822/46170 | egress 1.0067 | named 134334/1454, <UNKNOWN> 3924488/44716 |
| s20 | High-rate parallel burst | 🟡 PART | ❌ FAIL | 8045376/- | 4558840/21550 | egress 0.5666 | named 0/0, <UNKNOWN> 4558840/21550 |
| s21 | io_uring download (recv) | 🟡 PART | 🟡 PART* | -/25195912 | 106240/23406800 | ingress 0.929 | named 0/0, <UNKNOWN> 106240/23406800 |
| s22 | splice() zero-copy download | ✅ PASS | ✅ PASS | -/33587400 | 66419/33959752 | ingress 1.0111 | named 64091/32565960, <UNKNOWN> 2328/1393792 |
| s23 | recvmmsg batched UDP (recv) | ✅ PASS | ✅ PASS | -/25309632 | 2090/26375712 | ingress 1.0421 | named 30/24475260, <UNKNOWN> 2060/1900452 |
| s24 | IPv6 UDP download | ✅ PASS | ✅ PASS | -/25309632 | 30/24830176 | ingress 0.9811 | named 30/22912380, <UNKNOWN> 0/1917796 |
