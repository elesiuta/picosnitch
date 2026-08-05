# Sysdig: detailed results

- scored against: **application bytes**, except s12 (AF_PACKET), scored against wire bytes (L3 + Ethernet header per packet): a packet-socket write is an ordinary sendto whose bytes are the whole frame

- **control (separate from the s01 row):** det=PASS bw=PASS (reference recv=33554432, reported recv=33554432)

Rows show the first trial's numbers; verdicts combine all trials. \* = trials disagreed.

| # | Scenario | Det | BW | reference s/r | reported s/r | ratio | note |
|---|---|---|---|---|---|---|---|
| s01 | TCP bulk download (control) | ✅ PASS | ✅ PASS | -/33554432 | 24/33554432 | ingress 1.0 | Sysdig network I/O syscall bytes, per process |
| s02 | TCP bulk upload | ✅ PASS | ✅ PASS | 33554456/- | 33554456/0 | egress 1.0 | Sysdig network I/O syscall bytes, per process |
| s03 | TCP full-duplex up+down | ✅ PASS | ✅ PASS | 25165872/25165824 | 25165872/25165824 | egress 1.0 ingress 1.0 | Sysdig network I/O syscall bytes, per process |
| s04 | UDP bulk up+down | ✅ PASS | ✅ PASS | 25166448/25165824 | 25166448/25165824 | egress 1.0 ingress 1.0 | Sysdig network I/O syscall bytes, per process |
| s05 | ICMP echo flood w/ payload | ✅ PASS | ✅ PASS | 6342336/6468176 | 6342336/6468176 | egress 1.0 ingress 1.0 | Sysdig network I/O syscall bytes, per process |
| s06 | UDP/443 bulk | ✅ PASS | ✅ PASS | 25166424/- | 25166424/0 | egress 1.0 | Sysdig network I/O syscall bytes, per process |
| s07 | IPv6 TCP transfer | ✅ PASS | ✅ PASS | -/25165824 | 24/25165824 | ingress 1.0 | Sysdig network I/O syscall bytes, per process |
| s08 | SCTP transfer | ✅ PASS | ✅ PASS | -/25165824 | 24/25165824 | ingress 1.0 | Sysdig network I/O syscall bytes, per process |
| s09 | Small-packet UDP/53 flood | ✅ PASS | ✅ PASS | 4194328/- | 4194328/0 | egress 1.0 | Sysdig network I/O syscall bytes, per process |
| s10 | Raw IP socket (proto 253) egress | ✅ PASS | ✅ PASS | 4194304/- | 4194304/0 | egress 1.0 | Sysdig network I/O syscall bytes, per process |
| s11 | Short-lived processes | ✅ PASS | ✅ PASS | 10486240/- | 10486240/0 | egress 1.0 | Sysdig network I/O syscall bytes, per process |
| s12 | AF_PACKET raw-frame injection | ✅ PASS | ✅ PASS | 4320136/- | 4320136/0 | egress 1.0 | Sysdig network I/O syscall bytes, per process |
| s13 | io_uring data path | ✅ PASS | ❌ FAIL | 25165848/- | 24/0 | egress 0.0 | Sysdig network I/O syscall bytes, per process |
| s14 | sendfile() zero-copy upload | ✅ PASS | ❌ FAIL | 33554456/- | 24/0 | egress 0.0 | Sysdig network I/O syscall bytes, per process |
| s15 | sendmmsg batched UDP | ✅ PASS | ✅ PASS | 25177624/- | 25964424/0 | egress 1.0312 | Sysdig network I/O syscall bytes, per process |
| s16 | Loopback-only transfer | ✅ PASS | ✅ PASS | -/25165824 | 24/25165824 | ingress 1.0 | Sysdig network I/O syscall bytes, per process |
| s17 | In-container (docker) egress | ✅ PASS | ✅ PASS | 25165848/- | 25165848/0 | egress 1.0 | Sysdig network I/O syscall bytes, per process |
| s18 | Low-and-slow drip upload | ✅ PASS | ✅ PASS | 2097176/- | 2097176/0 | egress 1.0 | Sysdig network I/O syscall bytes, per process |
| s19 | Many small TCP connections | ✅ PASS | ✅ PASS | 3933600/- | 3933600/0 | egress 1.0 | Sysdig network I/O syscall bytes, per process |
| s20 | High-rate parallel burst | ✅ PASS | ✅ PASS | 7865040/- | 7865040/0 | egress 1.0 | Sysdig network I/O syscall bytes, per process |
| s21 | io_uring download (recv) | ✅ PASS | ❌ FAIL | -/25165824 | 24/0 | ingress 0.0 | Sysdig network I/O syscall bytes, per process |
| s22 | splice() zero-copy download | ✅ PASS | ❌ FAIL | -/33554432 | 24/0 | ingress 0.0 | Sysdig network I/O syscall bytes, per process |
| s23 | recvmmsg batched UDP (recv) | ✅ PASS | ❌ FAIL | -/25165824 | 24/49025448 | ingress 1.9481 | Sysdig network I/O syscall bytes, per process |
| s24 | IPv6 UDP download | ✅ PASS | ✅ PASS | -/25165824 | 24/25165824 | ingress 1.0 | Sysdig network I/O syscall bytes, per process |
