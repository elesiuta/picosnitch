# bpftrace script: detailed results

- layer scored against: **socket** (app-layer bytes)

- **control (separate from the s01 row):** det=PASS bw=PASS (ref recv=33554432, reported recv=33554432)

| # | Scenario | Det | BW | ref app s/r | ref wire s/r | reported s/r | ratio | note |
|---|---|---|---|---|---|---|---|---|
| s01 | TCP bulk download (control) | ✅ PASS | ✅ PASS | 24/33554432 | 45532/33608000 | 24/33554432 | ingress 1.0 | bpftrace tcp_sendmsg/tcp_cleanup_rbuf, summed per second |
| s02 | TCP bulk upload | ✅ PASS | ✅ PASS | 33554456/0 | 34779428/33756 | 33554456/0 | egress 1.0 | bpftrace tcp_sendmsg/tcp_cleanup_rbuf, summed per second |
| s03 | TCP full-duplex up+down | ✅ PASS | ✅ PASS | 25165872/25165824 | 26126952/25238120 | 25165872/25165824 | egress 1.0 | bpftrace tcp_sendmsg/tcp_cleanup_rbuf, summed per second |
| s04 | UDP bulk up+down | ⬜ N/A | ⬜ N/A | 25166448/25165824 | 25669832/25669152 | -/- |  | this bpftrace probe hooks tcp_* only (TCP) |
| s05 | ICMP echo flood w/ payload | ⬜ N/A | ⬜ N/A | 6342336/6468176 | 6468176/6468176 | -/- |  | this bpftrace probe hooks tcp_* only (TCP) |
| s06 | UDP/443 bulk | ⬜ N/A | ⬜ N/A | 25166424/0 | 25669780/0 | -/- |  | this bpftrace probe hooks tcp_* only (TCP) |
| s07 | IPv6 TCP transfer | ✅ PASS | ✅ PASS | 24/25165824 | 50360/25221560 | 24/25165824 | ingress 1.0 | bpftrace tcp_sendmsg/tcp_cleanup_rbuf, summed per second |
| s08 | SCTP transfer | ⬜ N/A | ⬜ N/A | 24/25165824 | 424472/25572252 | -/- |  | this bpftrace probe hooks tcp_* only (TCP) |
| s09 | Small-packet UDP/53 flood | ⬜ N/A | ⬜ N/A | 4194328/0 | 6029364/0 | -/- |  | this bpftrace probe hooks tcp_* only (TCP) |
| s10 | Raw IP socket (proto 253) egress | ⬜ N/A | ⬜ N/A | 4194304/0 | 4254224/0 | -/- |  | this bpftrace probe hooks tcp_* only (TCP) |
| s11 | Short-lived processes | ✅ PASS | ✅ PASS | 10486240/0 | 10871044/38952 | 10486240/0 | egress 1.0 | bpftrace tcp_sendmsg/tcp_cleanup_rbuf, summed per second |
| s12 | AF_PACKET raw-frame injection | ⬜ N/A | ⬜ N/A | 4194304/0 | 4278192/0 | -/- |  | this bpftrace probe hooks tcp_* only (TCP) |
| s13 | io_uring data path | ✅ PASS | ✅ PASS | 25165848/0 | 26083240/31416 | 25267024/0 | egress 1.004 | bpftrace tcp_sendmsg/tcp_cleanup_rbuf, summed per second |
| s14 | sendfile() zero-copy upload | ✅ PASS | ✅ PASS | 33554456/0 | 34779376/39372 | 33554456/0 | egress 1.0 | bpftrace tcp_sendmsg/tcp_cleanup_rbuf, summed per second |
| s15 | sendmmsg batched UDP | ⬜ N/A | ⬜ N/A | 25177624/0 | 25681204/0 | -/- |  | this bpftrace probe hooks tcp_* only (TCP) |
| s16 | Loopback-only transfer | ✅ PASS | ✅ PASS | 24/25165824 | 24/25165824 | 24/25165824 | ingress 1.0 | bpftrace tcp_sendmsg/tcp_cleanup_rbuf, summed per second |
| s17 | In-container (docker) egress | ✅ PASS | ✅ PASS | 25165848/0 | 26084644/30844 | 25165848/0 | egress 1.0 | bpftrace tcp_sendmsg/tcp_cleanup_rbuf, summed per second |
| s18 | Low-and-slow drip upload | ✅ PASS | ✅ PASS | 2097176/0 | 2173988/31364 | 2097176/0 | egress 1.0 | bpftrace tcp_sendmsg/tcp_cleanup_rbuf, summed per second |
| s19 | Many small TCP connections | ✅ PASS | ✅ PASS | 3933600/0 | 4093200/75204 | 3933600/0 | egress 1.0 | bpftrace tcp_sendmsg/tcp_cleanup_rbuf, summed per second |
| s20 | High-rate parallel burst | ✅ PASS | ✅ PASS | 7865040/0 | 8157520/49432 | 7865040/0 | egress 1.0 | bpftrace tcp_sendmsg/tcp_cleanup_rbuf, summed per second |
| s21 | io_uring download (recv) | ✅ PASS | ❌ FAIL | 24/25165824 | 126256/25208404 | 24/1864040967514 | ingress 74070.3331 | bpftrace tcp_sendmsg/tcp_cleanup_rbuf, summed per second |
| s22 | splice() zero-copy download | ✅ PASS | ✅ PASS | 24/33554432 | 85520/33608000 | 24/33554432 | ingress 1.0 | bpftrace tcp_sendmsg/tcp_cleanup_rbuf, summed per second |
| s23 | recvmmsg batched UDP (recv) | ⬜ N/A | ⬜ N/A | 24/25165824 | 52/25669152 | -/- |  | this bpftrace probe hooks tcp_* only (TCP) |
| s24 | IPv6 UDP download | ⬜ N/A | ⬜ N/A | 24/25165824 | 72/26028672 | -/- |  | this bpftrace probe hooks tcp_* only (TCP) |
