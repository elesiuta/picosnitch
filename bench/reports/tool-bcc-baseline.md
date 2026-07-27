# BCC tcplife/tcpconnect — detailed results

- layer scored against: **socket** (app-layer bytes)

- **control (bulk TCP download smoke transfer, separate from the s01 row):** det=PASS bw=PASS (gt recv=33554432, reported recv=33554432)

| # | Scenario | Det | BW | GT app s/r | GT wire s/r | reported s/r | ratio | note |
|---|---|---|---|---|---|---|---|---|
| s01 | TCP bulk download (control) | ✅ PASS | ✅ PASS | 24/33554432 | 50004/33607948 | 0/33554432 | ingress 1.0 | tcplife fires on session close |
| s02 | TCP bulk upload | ✅ PASS | ✅ PASS | 33554456/0 | 34779428/38072 | 33554432/0 | egress 1.0 | tcplife fires on session close |
| s03 | TCP full-duplex up+down | 🟡 PART | ✅ PASS | 25165872/25165824 | 26122376/25239316 | 25165824/25165824 | egress 1.0 | tcplife fires on session close |
| s04 | UDP bulk up+down | ⬜ N/A | ⬜ N/A | 25166448/25165824 | 25669832/25669152 | -/- |  | bcc tcplife/tcpconnect are TCP-only |
| s05 | ICMP echo flood w/ payload | ⬜ N/A | ⬜ N/A | 6342336/6468176 | 6468176/6468176 | -/- |  | bcc tcplife/tcpconnect are TCP-only |
| s06 | UDP/443 bulk | ⬜ N/A | ⬜ N/A | 25166424/0 | 25669780/0 | -/- |  | bcc tcplife/tcpconnect are TCP-only |
| s07 | IPv6 TCP transfer | ✅ PASS | ✅ PASS | 24/25165824 | 49064/25221632 | 0/25165824 | ingress 1.0 | tcplife fires on session close |
| s08 | SCTP transfer | ⬜ N/A | ⬜ N/A | 24/25165824 | 424472/25572252 | -/- |  | bcc tcplife/tcpconnect are TCP-only |
| s09 | Small-packet UDP/53 flood | ⬜ N/A | ⬜ N/A | 4194328/0 | 6029364/0 | -/- |  | bcc tcplife/tcpconnect are TCP-only |
| s10 | Raw IP socket (proto 253) egress | ⬜ N/A | ⬜ N/A | 4194304/0 | 4254224/0 | -/- |  | bcc tcplife/tcpconnect are TCP-only |
| s11 | Short-lived processes | ✅ PASS | ✅ PASS | 10486240/0 | 10870992/47636 | 10485760/1048576 | egress 1.0 | tcplife fires on session close |
| s12 | AF_PACKET raw-frame injection | ⬜ N/A | ⬜ N/A | 4194304/0 | 4278192/0 | -/- |  | bcc tcplife/tcpconnect are TCP-only |
| s13 | io_uring data path | ✅ PASS | ✅ PASS | 25165848/0 | 26084540/47536 | 25165824/25165824 | egress 1.0 | tcplife fires on session close |
| s14 | sendfile() zero-copy upload | ✅ PASS | ✅ PASS | 33554456/0 | 34779428/39736 | 33554432/0 | egress 1.0 | tcplife fires on session close |
| s15 | sendmmsg batched UDP | ⬜ N/A | ⬜ N/A | 25177624/0 | 25681204/0 | -/- |  | bcc tcplife/tcpconnect are TCP-only |
| s16 | Loopback-only transfer | ✅ PASS | ✅ PASS | 24/25165824 | 24/25165824 | 0/25165824 | ingress 1.0 | tcplife fires on session close |
| s17 | In-container (docker) egress | ✅ PASS | ✅ PASS | 25165848/0 | 26084644/25384 | 25165824/0 | egress 1.0 | tcplife fires on session close |
| s18 | Low-and-slow drip upload | ✅ PASS | ✅ PASS | 2097176/0 | 2173988/31156 | 2097152/0 | egress 1.0 | tcplife fires on session close |
| s19 | Many small TCP connections | ✅ PASS | ✅ PASS | 3933600/0 | 4093200/74996 | 3932160/0 | egress 0.9996 | tcplife fires on session close |
| s20 | High-rate parallel burst | ✅ PASS | ✅ PASS | 7865040/0 | 8157520/52344 | 7864320/1310720 | egress 0.9999 | tcplife fires on session close |
| s21 | io_uring download (recv) | 🟡 PART | ✅ PASS | 24/25165824 | 118644/25207068 | 25165824/25165824 | ingress 1.0 | tcplife fires on session close |
| s22 | splice() zero-copy download | 🟡 PART | ✅ PASS | 24/33554432 | 90980/33608000 | 0/33554432 | ingress 1.0 | tcplife fires on session close |
| s23 | recvmmsg batched UDP (recv) | ⬜ N/A | ⬜ N/A | 24/25165824 | 52/25669152 | -/- |  | bcc tcplife/tcpconnect are TCP-only |
| s24 | IPv6 UDP download | ⬜ N/A | ⬜ N/A | 24/25165824 | 72/26028672 | -/- |  | bcc tcplife/tcpconnect are TCP-only |
