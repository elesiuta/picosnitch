# OpenSnitch: detailed results

- scored against: **application bytes**

- **control (separate from the s01 row):** det=PASS bw=N/A (reference recv=33554432, reported recv=-)

Rows show the first trial's numbers; verdicts combine all trials. \* = trials disagreed.

| # | Scenario | Det | BW | reference s/r | reported s/r | ratio | note |
|---|---|---|---|---|---|---|---|
| s01 | TCP bulk download (control) | ✅ PASS | ⬜ N/A | -/- | -/- |  | 1 connection record(s) matched process |
| s02 | TCP bulk upload | ✅ PASS | ⬜ N/A | -/- | -/- |  | 1 connection record(s) matched process |
| s03 | TCP full-duplex up+down | ✅ PASS | ⬜ N/A | -/- | -/- |  | 2 connection record(s) matched process |
| s04 | UDP bulk up+down | ✅ PASS* | ⬜ N/A | -/- | -/- |  | 17974 connection record(s) matched process |
| s05 | ICMP echo flood w/ payload | ❌ FAIL | ⬜ N/A | -/- | -/- |  | 0 connection record(s) matched process |
| s06 | UDP/443 bulk | ✅ PASS* | ⬜ N/A | -/- | -/- |  | 17975 connection record(s) matched process |
| s07 | IPv6 TCP transfer | ✅ PASS | ⬜ N/A | -/- | -/- |  | 1 connection record(s) matched process |
| s08 | SCTP transfer | ✅ PASS | ⬜ N/A | -/- | -/- |  | 1 connection record(s) matched process |
| s09 | Small-packet UDP/53 flood | ✅ PASS* | ⬜ N/A | -/- | -/- |  | 15010 connection record(s) matched process |
| s10 | Raw IP socket (proto 253) egress | ❌ FAIL | ⬜ N/A | -/- | -/- |  | 0 connection record(s) matched process |
| s11 | Short-lived processes | ✅ PASS | ⬜ N/A | -/- | -/- |  | 20 connection record(s) matched process |
| s12 | AF_PACKET raw-frame injection | ❌ FAIL | ⬜ N/A | -/- | -/- |  | 0 connection record(s) matched process |
| s13 | io_uring data path | ✅ PASS | ⬜ N/A | -/- | -/- |  | 1 connection record(s) matched process |
| s14 | sendfile() zero-copy upload | ✅ PASS | ⬜ N/A | -/- | -/- |  | 1 connection record(s) matched process |
| s15 | sendmmsg batched UDP | ✅ PASS | ⬜ N/A | -/- | -/- |  | 17985 connection record(s) matched process |
| s16 | Loopback-only transfer | ❌ FAIL | ⬜ N/A | -/- | -/- |  | 0 connection record(s) matched process |
| s17 | In-container (docker) egress | ❌ FAIL | ⬜ N/A | -/- | -/- |  | 0 connection record(s) matched process |
| s18 | Low-and-slow drip upload | ✅ PASS | ⬜ N/A | -/- | -/- |  | 1 connection record(s) matched process |
| s19 | Many small TCP connections | ✅ PASS | ⬜ N/A | -/- | -/- |  | 60 connection record(s) matched process |
| s20 | High-rate parallel burst | ✅ PASS | ⬜ N/A | -/- | -/- |  | 30 connection record(s) matched process |
| s21 | io_uring download (recv) | ✅ PASS | ⬜ N/A | -/- | -/- |  | 1 connection record(s) matched process |
| s22 | splice() zero-copy download | ✅ PASS | ⬜ N/A | -/- | -/- |  | 1 connection record(s) matched process |
| s23 | recvmmsg batched UDP (recv) | ✅ PASS | ⬜ N/A | -/- | -/- |  | 1 connection record(s) matched process |
| s24 | IPv6 UDP download | ✅ PASS | ⬜ N/A | -/- | -/- |  | 1 connection record(s) matched process |
