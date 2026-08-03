# bpftrace script: detailed results

- scored against: **application bytes**

- **control (separate from the s01 row):** det=PASS bw=PASS (reference recv=33554432, reported recv=33554432)

Rows show the first trial's numbers; verdicts combine all trials. \* = trials disagreed.

| # | Scenario | Det | BW | reference s/r | reported s/r | ratio | note |
|---|---|---|---|---|---|---|---|
| s01 | TCP bulk download (control) | ✅ PASS | ✅ PASS | -/33554432 | 24/33554432 | ingress 1.0 | bpftrace tcp_sendmsg/tcp_cleanup_rbuf, summed per second |
| s02 | TCP bulk upload | ✅ PASS | ✅ PASS | 33554456/- | 33554456/0 | egress 1.0 | bpftrace tcp_sendmsg/tcp_cleanup_rbuf, summed per second |
| s03 | TCP full-duplex up+down | ✅ PASS | ✅ PASS | 25165872/25165824 | 25165872/25165824 | egress 1.0 ingress 1.0 | bpftrace tcp_sendmsg/tcp_cleanup_rbuf, summed per second |
| s04 | UDP bulk up+down | ⬜ N/A | ⬜ N/A | -/- | -/- |  | this bpftrace probe hooks tcp_* only (TCP) |
| s05 | ICMP echo flood w/ payload | ⬜ N/A | ⬜ N/A | -/- | -/- |  | this bpftrace probe hooks tcp_* only (TCP) |
| s06 | UDP/443 bulk | ⬜ N/A | ⬜ N/A | -/- | -/- |  | this bpftrace probe hooks tcp_* only (TCP) |
| s07 | IPv6 TCP transfer | ✅ PASS | ✅ PASS | -/25165824 | 24/25165824 | ingress 1.0 | bpftrace tcp_sendmsg/tcp_cleanup_rbuf, summed per second |
| s08 | SCTP transfer | ⬜ N/A | ⬜ N/A | -/- | -/- |  | this bpftrace probe hooks tcp_* only (TCP) |
| s09 | Small-packet UDP/53 flood | ⬜ N/A | ⬜ N/A | -/- | -/- |  | this bpftrace probe hooks tcp_* only (TCP) |
| s10 | Raw IP socket (proto 253) egress | ⬜ N/A | ⬜ N/A | -/- | -/- |  | this bpftrace probe hooks tcp_* only (TCP) |
| s11 | Short-lived processes | ✅ PASS | ✅ PASS | 10486240/- | 10486240/0 | egress 1.0 | bpftrace tcp_sendmsg/tcp_cleanup_rbuf, summed per second |
| s12 | AF_PACKET raw-frame injection | ⬜ N/A | ⬜ N/A | -/- | -/- |  | this bpftrace probe hooks tcp_* only (TCP) |
| s13 | io_uring data path | ✅ PASS | ✅ PASS | 25165848/- | 25290056/0 | egress 1.0049 | bpftrace tcp_sendmsg/tcp_cleanup_rbuf, summed per second |
| s14 | sendfile() zero-copy upload | ✅ PASS | ✅ PASS | 33554456/- | 33554456/0 | egress 1.0 | bpftrace tcp_sendmsg/tcp_cleanup_rbuf, summed per second |
| s15 | sendmmsg batched UDP | ⬜ N/A | ⬜ N/A | -/- | -/- |  | this bpftrace probe hooks tcp_* only (TCP) |
| s16 | Loopback-only transfer | ✅ PASS | ✅ PASS | -/25165824 | 24/25165824 | ingress 1.0 | bpftrace tcp_sendmsg/tcp_cleanup_rbuf, summed per second |
| s17 | In-container (docker) egress | ✅ PASS | ✅ PASS | 25165848/- | 25165848/0 | egress 1.0 | bpftrace tcp_sendmsg/tcp_cleanup_rbuf, summed per second |
| s18 | Low-and-slow drip upload | ✅ PASS | ✅ PASS | 2097176/- | 2097176/0 | egress 1.0 | bpftrace tcp_sendmsg/tcp_cleanup_rbuf, summed per second |
| s19 | Many small TCP connections | ✅ PASS | ✅ PASS | 3933600/- | 3933600/0 | egress 1.0 | bpftrace tcp_sendmsg/tcp_cleanup_rbuf, summed per second |
| s20 | High-rate parallel burst | ✅ PASS | ✅ PASS | 7865040/- | 7865040/0 | egress 1.0 | bpftrace tcp_sendmsg/tcp_cleanup_rbuf, summed per second |
| s21 | io_uring download (recv) | ✅ PASS | ✅ PASS | -/25165824 | 24/25165824 | ingress 1.0 | bpftrace tcp_sendmsg/tcp_cleanup_rbuf, summed per second |
| s22 | splice() zero-copy download | ✅ PASS | ✅ PASS | -/33554432 | 24/33554432 | ingress 1.0 | bpftrace tcp_sendmsg/tcp_cleanup_rbuf, summed per second |
| s23 | recvmmsg batched UDP (recv) | ⬜ N/A | ⬜ N/A | -/- | -/- |  | this bpftrace probe hooks tcp_* only (TCP) |
| s24 | IPv6 UDP download | ⬜ N/A | ⬜ N/A | -/- | -/- |  | this bpftrace probe hooks tcp_* only (TCP) |
