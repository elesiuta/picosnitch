# opensnitch — detailed results

- layer scored against: **socket** (app-layer bytes)
- does bandwidth: False · does per-process attribution: True

- **control (bulk TCP download smoke transfer, separate from the s01 row):** det=PASS bw=N/A (gt recv=33554432, reported recv=-)

| # | Scenario | Det | BW | GT app s/r | GT wire s/r | reported s/r | ratio | note |
|---|---|---|---|---|---|---|---|---|
| s01 | TCP bulk download (control) | ✅ PASS | ⬜ N/A | 24/33554432 | 45584/33607948 | -/- |  | 1 connection record(s) matched process |
| s02 | TCP bulk upload | ✅ PASS | ⬜ N/A | 33554456/0 | 34779428/38020 | -/- |  | 1 connection record(s) matched process |
| s03 | TCP full-duplex up+down | ✅ PASS | ⬜ N/A | 25165872/25165824 | 26122324/25236612 | -/- |  | 2 connection record(s) matched process |
| s04 | UDP bulk up+down | ✅ PASS⚡ | ⬜ N/A | 25166448/25165824 | 25669832/25669152 | -/- |  | 17978 connection record(s) matched process |
| s05 | ICMP echo flood w/ payload | ❌ FAIL | ⬜ N/A | 6342336/6468176 | 6468176/6468176 | -/- |  | 0 connection record(s) matched process |
| s06 | QUIC-style UDP:443 bulk | ✅ PASS⚡ | ⬜ N/A | 25166424/0 | 25669780/0 | -/- |  | 17970 connection record(s) matched process |
| s07 | IPv6 TCP transfer | ✅ PASS⚡ | ⬜ N/A | 24/25165824 | 67568/25221632 | -/- |  | 0 connection record(s) matched process |
| s08 | SCTP transfer | ✅ PASS | ⬜ N/A | 24/25165824 | 424472/25572252 | -/- |  | 1 connection record(s) matched process |
| s09 | DNS-style small UDP:53 flood | ✅ PASS⚡ | ⬜ N/A | 4194328/0 | 1023644/0 | -/- |  | 15182 connection record(s) matched process |
| s10 | Raw IP socket (proto 253) egress | ❌ FAIL | ⬜ N/A | 274400/0 | 252760/0 | -/- |  | 0 connection record(s) matched process |
| s11 | Short-lived processes | ✅ PASS | ⬜ N/A | 10486240/0 | 10872708/51848 | -/- |  | 20 connection record(s) matched process |
| s12 | AF_PACKET raw-frame injection | ❌ FAIL⚡ | ⬜ N/A | 4194304/0 | 4278192/0 | -/- |  | 0 connection record(s) matched process; flow seen by dst only |
| s13 | io_uring data path | ✅ PASS | ⬜ N/A | 25165848/0 | 26083760/45820 | -/- |  | 1 connection record(s) matched process |
| s14 | sendfile() zero-copy upload | ✅ PASS | ⬜ N/A | 33554456/0 | 34797960/43268 | -/- |  | 1 connection record(s) matched process |
| s15 | sendmmsg batched UDP | ✅ PASS⚡ | ⬜ N/A | 25177624/0 | 25681204/0 | -/- |  | 17984 connection record(s) matched process |
| s16 | Loopback-only transfer | ❌ FAIL | ⬜ N/A | 24/25165824 | 24/25165824 | -/- |  | 0 connection record(s) matched process |
| s17 | In-container (docker) egress | ❌ FAIL | ⬜ N/A | 25165848/0 | 26084644/31676 | -/- |  | 0 connection record(s) matched process |
| s18 | Low-and-slow drip upload | ✅ PASS | ⬜ N/A | 2097176/0 | 2173988/27152 | -/- |  | 1 connection record(s) matched process |
| s19 | Many small TCP connections | ✅ PASS | ⬜ N/A | 3933600/0 | 4093200/73800 | -/- |  | 60 connection record(s) matched process |
| s20 | High-rate parallel burst | ✅ PASS | ⬜ N/A | 7865040/0 | 8158196/45428 | -/- |  | 30 connection record(s) matched process |
| s21 | io_uring download (recv) | ✅ PASS | ⬜ N/A | 24/25165824 | 175376/25211228 | -/- |  | 1 connection record(s) matched process |
| s22 | splice() zero-copy download | ✅ PASS | ⬜ N/A | 24/33554432 | 139860/33608052 | -/- |  | 1 connection record(s) matched process |
| s23 | recvmmsg batched UDP (recv) | ✅ PASS | ⬜ N/A | 24/25165824 | 52/25669152 | -/- |  | 1 connection record(s) matched process |
| s24 | IPv6 UDP download | ✅ PASS | ⬜ N/A | 24/25165824 | 72/26028672 | -/- |  | 1 connection record(s) matched process |

⚡/\* rows: trials disagreed; the table shows the first trial's numbers, while the verdict combines all trials (best-of-5 for sniffnet).
