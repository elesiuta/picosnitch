# sysdig — detailed results

- layer scored against: **socket** (app-layer bytes)
- does bandwidth: True · does per-process attribution: True

- **control (bulk TCP download smoke transfer, separate from the s01 row):** det=PASS bw=PASS (gt recv=33554432, reported recv=33554432)

| # | Scenario | Det | BW | GT app s/r | GT wire s/r | reported s/r | ratio | note |
|---|---|---|---|---|---|---|---|---|
| s01 | TCP bulk download (control) | ✅ PASS | ✅ PASS | 24/33554432 | 35652/33608000 | 24/33554432 | ingress 1.0 | sysdig network I/O syscall bytes, per process |
| s02 | TCP bulk upload | ✅ PASS | ✅ PASS | 33554456/0 | 34779428/37812 | 33554456/0 | egress 1.0 | sysdig network I/O syscall bytes, per process |
| s03 | TCP full-duplex up+down | ✅ PASS | ✅ PASS | 25165872/25165824 | 26121700/25228916 | 25165872/25165824 | egress 1.0 | sysdig network I/O syscall bytes, per process |
| s04 | UDP bulk up+down | ✅ PASS | ✅ PASS | 25166448/25165824 | 25669832/25669152 | 25166448/25165824 | egress 1.0 | sysdig network I/O syscall bytes, per process |
| s05 | ICMP echo flood w/ payload | ✅ PASS | ✅ PASS | 6342336/6468176 | 6468176/6468176 | 6342336/6468176 | egress 1.0 | sysdig network I/O syscall bytes, per process |
| s06 | QUIC-style UDP:443 bulk | ✅ PASS | ✅ PASS | 25166424/0 | 25669780/0 | 25166424/0 | egress 1.0 | sysdig network I/O syscall bytes, per process |
| s07 | IPv6 TCP transfer | ✅ PASS | ✅ PASS | 24/25165824 | 46400/25221632 | 24/25165824 | ingress 1.0 | sysdig network I/O syscall bytes, per process |
| s08 | SCTP transfer | ✅ PASS | ✅ PASS | 24/25165824 | 424472/25572252 | 24/25165824 | ingress 1.0 | sysdig network I/O syscall bytes, per process |
| s09 | DNS-style small UDP:53 flood | ✅ PASS | ✅ PASS | 4194328/0 | 6029364/0 | 4194328/0 | egress 1.0 | sysdig network I/O syscall bytes, per process |
| s10 | Raw IP socket (proto 253) egress | ✅ PASS | ✅ PASS | 4194304/0 | 4254224/0 | 4194304/0 | egress 1.0 | sysdig network I/O syscall bytes, per process |
| s11 | Short-lived processes | ✅ PASS | ✅ PASS | 10486240/0 | 10870472/37132 | 10486240/0 | egress 1.0 | sysdig network I/O syscall bytes, per process |
| s12 | AF_PACKET raw-frame injection | ❌ FAIL | ❌ FAIL | 4194304/0 | 4278192/0 | 0/0 | egress 0.0 | AF_PACKET bypasses sysdig's network syscall accounting |
| s13 | io_uring data path | ✅ PASS | ❌ FAIL | 25165848/0 | 26083188/29908 | 24/0 | egress 0.0 | sysdig network I/O syscall bytes, per process |
| s14 | sendfile() zero-copy upload | ✅ PASS | ❌ FAIL | 33554456/0 | 34779428/35160 | 24/0 | egress 0.0 | sysdig network I/O syscall bytes, per process |
| s15 | sendmmsg batched UDP | ✅ PASS | ✅ PASS | 25177624/0 | 25681204/0 | 25964424/0 | egress 1.0312 | sysdig network I/O syscall bytes, per process |
| s16 | Loopback-only transfer | ✅ PASS | ✅ PASS | 24/25165824 | 24/25165824 | 24/25165824 | ingress 1.0 | sysdig network I/O syscall bytes, per process |
| s17 | In-container (docker) egress | ✅ PASS | ✅ PASS | 25165848/0 | 26084644/36512 | 25165848/0 | egress 1.0 | sysdig network I/O syscall bytes, per process |
| s18 | Low-and-slow drip upload | ✅ PASS | ✅ PASS | 2097176/0 | 2173988/29336 | 2097176/0 | egress 1.0 | sysdig network I/O syscall bytes, per process |
| s19 | Many small TCP connections | ✅ PASS | ✅ PASS | 3933600/0 | 4093200/75256 | 3933600/0 | egress 1.0 | sysdig network I/O syscall bytes, per process |
| s20 | High-rate parallel burst | ✅ PASS | ✅ PASS | 7865040/0 | 8157572/48340 | 7865040/0 | egress 1.0 | sysdig network I/O syscall bytes, per process |
| s21 | io_uring download (recv) | ✅ PASS | ❌ FAIL | 24/25165824 | 128212/25206132 | 24/0 | ingress 0.0 | sysdig network I/O syscall bytes, per process |
| s22 | splice() zero-copy download | ✅ PASS | ❌ FAIL | 24/33554432 | 95192/33608000 | 24/0 | ingress 0.0 | sysdig network I/O syscall bytes, per process |
| s23 | recvmmsg batched UDP (recv) | ✅ PASS | ❌ FAIL | 24/25165824 | 52/25669152 | 24/50026448 | ingress 1.9879 | sysdig network I/O syscall bytes, per process |
| s24 | IPv6 UDP download | ✅ PASS | ✅ PASS | 24/25165824 | 72/26028672 | 24/25165824 | ingress 1.0 | sysdig network I/O syscall bytes, per process |
