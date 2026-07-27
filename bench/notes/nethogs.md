# nethogs — benchmark notes

- **Pinned version:** v0.8.8 (latest tagged release, 2024-10-07), built from source.
  No prebuilt binaries on GitHub releases; built from the v0.8.8 tag (Ubuntu
  26.04's package is also 0.8.8-1 — the tag pin stays distro-independent).
- **Build deps:** `build-essential libpcap-dev libncurses-dev`. `make && make install` → `/usr/local/sbin/nethogs`.
- **Measures:** per-process **bandwidth**, at the **wire** layer (`header->len`, includes IP/TCP/UDP headers + retransmissions).

## Headless extraction
- Command: `nethogs -t -C -v 2 -a -d 1 <ifaces...>`
  - `-t` trace mode (line output, no ncurses)
  - `-C` **required** to account UDP (without it, `/proc/net/udp` is never read)
  - `-v 2` cumulative **total bytes** (monotonic since start; `-v 0` default is a kB/s *rate*, not a total)
  - `-a` include loopback (`lo`) — off by default
  - `-d 1` refresh every 1s
- Output line: `NAME/PID/UID<TAB>SENT<TAB>RECV`. The name may contain `/`, so split on TAB first, then `rsplit('/',2)`.
- Per-trial value = delta of the process's cumulative total between snapshots (monotonic → max == latest).

## Known limitations
- **No ICMP** — only TCP/UDP packet callbacks are registered. (scenario s05)
- **No SCTP / raw IP** — only `/proc/net/{tcp,udp}` are parsed. (s08, s10)
- **Short-lived processes** → bucketed as `unknown TCP` / `unknown UDP` (pid 0): /proc-scan attribution loses processes that exit before their packets are mapped. (s11)
- **Loopback** excluded unless `-a`. (s16)
- Precision: cumulative totals pass through a `float` and 6-sig-fig `std::cout` (scientific notation ≥1e6, rounding above ~16.7 MB) — below the ±10/25% comparison tolerance. Exact `uint64` only via `libnethogs`.
- SIGINT for clean stop (SIGTERM is *not* handled).
