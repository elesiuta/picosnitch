# BCC tcplife/tcpconnect: detailed results

- scored against: **application bytes**

- **control (separate from the s01 row):** det=PASS bw=PASS (reference recv=33554432, reported recv=33554432)

Rows show the first trial's numbers; verdicts combine all trials. \* = trials disagreed.

| # | Scenario | Det | BW | reference s/r | reported s/r | ratio | note |
|---|---|---|---|---|---|---|---|
| s01 | TCP bulk download (control) | ✅ PASS | ✅ PASS | -/33554432 | 0/33554432 | ingress 1.0 | tcplife fires on session close |
| s02 | TCP bulk upload | ✅ PASS | ✅ PASS | 33554456/- | 33554432/0 | egress 1.0 | tcplife fires on session close |
| s03 | TCP full-duplex up+down | ✅ PASS | ✅ PASS | 25165872/25165824 | 25165824/25165824 | egress 1.0 ingress 1.0 | tcplife fires on session close |
| s04 | UDP bulk up+down | ⬜ N/A | ⬜ N/A | -/- | -/- |  | bcc tcplife/tcpconnect are TCP-only |
| s05 | ICMP echo flood w/ payload | ⬜ N/A | ⬜ N/A | -/- | -/- |  | bcc tcplife/tcpconnect are TCP-only |
| s06 | UDP/443 bulk | ⬜ N/A | ⬜ N/A | -/- | -/- |  | bcc tcplife/tcpconnect are TCP-only |
| s07 | IPv6 TCP transfer | ✅ PASS | ✅ PASS | -/25165824 | 0/25165824 | ingress 1.0 | tcplife fires on session close |
| s08 | SCTP transfer | ⬜ N/A | ⬜ N/A | -/- | -/- |  | bcc tcplife/tcpconnect are TCP-only |
| s09 | Small-packet UDP/53 flood | ⬜ N/A | ⬜ N/A | -/- | -/- |  | bcc tcplife/tcpconnect are TCP-only |
| s10 | Raw IP socket (proto 253) egress | ⬜ N/A | ⬜ N/A | -/- | -/- |  | bcc tcplife/tcpconnect are TCP-only |
| s11 | Short-lived processes | ✅ PASS | ✅ PASS | 10486240/- | 10485760/0 | egress 1.0 | tcplife fires on session close |
| s12 | AF_PACKET raw-frame injection | ⬜ N/A | ⬜ N/A | -/- | -/- |  | bcc tcplife/tcpconnect are TCP-only |
| s13 | io_uring data path | ✅ PASS | ✅ PASS | 25165848/- | 25165824/25165824 | egress 1.0 | tcplife fires on session close |
| s14 | sendfile() zero-copy upload | ✅ PASS | ✅ PASS | 33554456/- | 33554432/0 | egress 1.0 | tcplife fires on session close |
| s15 | sendmmsg batched UDP | ⬜ N/A | ⬜ N/A | -/- | -/- |  | bcc tcplife/tcpconnect are TCP-only |
| s16 | Loopback-only transfer | ✅ PASS | ✅ PASS | -/25165824 | 0/25165824 | ingress 1.0 | tcplife fires on session close |
| s17 | In-container (docker) egress | ✅ PASS | ✅ PASS | 25165848/- | 25165824/0 | egress 1.0 | tcplife fires on session close |
| s18 | Low-and-slow drip upload | ✅ PASS | ✅ PASS | 2097176/- | 2097152/0 | egress 1.0 | tcplife fires on session close |
| s19 | Many small TCP connections | ✅ PASS | ✅ PASS | 3933600/- | 3932160/0 | egress 0.9996 | tcplife fires on session close |
| s20 | High-rate parallel burst | ✅ PASS | ✅ PASS | 7865040/- | 7864320/786432 | egress 0.9999 | tcplife fires on session close |
| s21 | io_uring download (recv) | ✅ PASS | ✅ PASS | -/25165824 | 25165824/25165824 | ingress 1.0 | tcplife fires on session close |
| s22 | splice() zero-copy download | ✅ PASS | ✅ PASS | -/33554432 | 0/33554432 | ingress 1.0 | tcplife fires on session close |
| s23 | recvmmsg batched UDP (recv) | ⬜ N/A | ⬜ N/A | -/- | -/- |  | bcc tcplife/tcpconnect are TCP-only |
| s24 | IPv6 UDP download | ⬜ N/A | ⬜ N/A | -/- | -/- |  | bcc tcplife/tcpconnect are TCP-only |
