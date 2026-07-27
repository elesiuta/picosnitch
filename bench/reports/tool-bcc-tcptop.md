# bcc tcptop — detailed results

- layer scored against: **socket** (app-layer bytes)
- does bandwidth: True · does per-process attribution: True

- **control (bulk TCP download smoke transfer, separate from the s01 row):** det=PASS bw=PASS (gt recv=33554432, reported recv=33554432)

| # | Scenario | Det | BW | GT app s/r | GT wire s/r | reported s/r | ratio | note |
|---|---|---|---|---|---|---|---|---|
| s01 | TCP bulk download (control) | ✅ PASS | ✅ PASS | 24/33554432 | 49380/33608000 | 0/33554432 | ingress 1.0 | tcptop per-interval KB summed over the trial |
| s02 | TCP bulk upload | ✅ PASS | ✅ PASS | 33554456/0 | 34779428/44520 | 33554432/0 | egress 1.0 | tcptop per-interval KB summed over the trial |
| s03 | TCP full-duplex up+down | ✅ PASS | ✅ PASS | 25165872/25165824 | 26125808/25232504 | 25165824/25165824 | egress 1.0 | tcptop per-interval KB summed over the trial |
| s04 | UDP bulk up+down | ⬜ N/A | ⬜ N/A | 25166448/25165824 | 25669832/25669152 | -/- |  | bcc tcptop is TCP-only |
| s05 | ICMP echo flood w/ payload | ⬜ N/A | ⬜ N/A | 6342336/6468176 | 6468176/6468176 | -/- |  | bcc tcptop is TCP-only |
| s06 | QUIC-style UDP:443 bulk | ⬜ N/A | ⬜ N/A | 25166424/0 | 25669780/0 | -/- |  | bcc tcptop is TCP-only |
| s07 | IPv6 TCP transfer | ✅ PASS | ✅ PASS | 24/25165824 | 46760/25221632 | 0/25165824 | ingress 1.0 | tcptop per-interval KB summed over the trial |
| s08 | SCTP transfer | ⬜ N/A | ⬜ N/A | 24/25165824 | 424472/25572252 | -/- |  | bcc tcptop is TCP-only |
| s09 | DNS-style small UDP:53 flood | ⬜ N/A | ⬜ N/A | 4194328/0 | 6029364/0 | -/- |  | bcc tcptop is TCP-only |
| s10 | Raw IP socket (proto 253) egress | ⬜ N/A | ⬜ N/A | 4194304/0 | 4254224/0 | -/- |  | bcc tcptop is TCP-only |
| s11 | Short-lived processes | ✅ PASS | ✅ PASS | 10486240/0 | 10871096/50080 | 10485760/0 | egress 1.0 | tcptop per-interval KB summed over the trial |
| s12 | AF_PACKET raw-frame injection | ⬜ N/A | ⬜ N/A | 4194304/0 | 4278192/0 | -/- |  | bcc tcptop is TCP-only |
| s13 | io_uring data path | ✅ PASS | ✅ PASS | 25165848/0 | 26084436/30272 | 25165824/0 | egress 1.0 | tcptop per-interval KB summed over the trial |
| s14 | sendfile() zero-copy upload | ✅ PASS | ✅ PASS | 33554456/0 | 34779428/41712 | 33554432/0 | egress 1.0 | tcptop per-interval KB summed over the trial |
| s15 | sendmmsg batched UDP | ⬜ N/A | ⬜ N/A | 25177624/0 | 25681204/0 | -/- |  | bcc tcptop is TCP-only |
| s16 | Loopback-only transfer | ✅ PASS | ✅ PASS | 24/25165824 | 24/25165824 | 0/25165824 | ingress 1.0 | tcptop per-interval KB summed over the trial |
| s17 | In-container (docker) egress | ✅ PASS | ✅ PASS | 25165848/0 | 26084644/40880 | 25165824/0 | egress 1.0 | tcptop per-interval KB summed over the trial |
| s18 | Low-and-slow drip upload | ✅ PASS | ✅ PASS | 2097176/0 | 2173988/28296 | 2097152/0 | egress 1.0 | tcptop per-interval KB summed over the trial |
| s19 | Many small TCP connections | ✅ PASS | ✅ PASS | 3933600/0 | 4093200/74736 | 3932160/0 | egress 0.9996 | tcptop per-interval KB summed over the trial |
| s20 | High-rate parallel burst | ✅ PASS | ✅ PASS | 7865040/0 | 8157936/54580 | 7864320/0 | egress 0.9999 | tcptop per-interval KB summed over the trial |
| s21 | io_uring download (recv) | ✅ PASS | ✅ PASS | 24/25165824 | 124052/25206132 | 0/25165824 | ingress 1.0 | tcptop per-interval KB summed over the trial |
| s22 | splice() zero-copy download | ✅ PASS | ❌ FAIL | 24/33554432 | 67372/33608000 | 0/0 | ingress 0.0 | tcptop per-interval KB summed over the trial |
| s23 | recvmmsg batched UDP (recv) | ⬜ N/A | ⬜ N/A | 24/25165824 | 52/25669152 | -/- |  | bcc tcptop is TCP-only |
| s24 | IPv6 UDP download | ⬜ N/A | ⬜ N/A | 24/25165824 | 72/26028672 | -/- |  | bcc tcptop is TCP-only |
