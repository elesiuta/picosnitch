# bandwhich — benchmark notes

- **Pinned version:** v0.23.1 (2024-10-08, still the latest release as of July 2026).
- **Install:** prebuilt static musl binary from GitHub releases (`bandwhich-v0.23.1-x86_64-unknown-linux-musl.tar.gz`). Zero runtime deps (uses `pnet` AF_PACKET, not libpcap).
- **Measures:** per-process **bandwidth**, at the **wire** layer (IP payload + headers as seen on the wire).

## Headless extraction
- Command: `bandwhich --raw --total-utilization --no-resolve`
  - `--raw` bypasses the TUI, prints one block per second
  - `--total-utilization` makes the per-process `up/down Bps` values **cumulative** (monotonic) — without it they're a 5-second rolling-average *rate*
  - `--no-resolve` keeps remote IPs stable (no reverse-DNS churn fragmenting keys)
- Line grammar: `process: <epoch> "<name>" up/down Bps: <up>/<down> connections: <n>`.
- Per-trial value = cumulative total for the (unique) process name.
- Auto-detects **all** interfaces (or a single `-i`); includes `lo`.

## Known limitations
- **TCP + UDP only, no ICMP** — the sniffer's protocol match drops everything else. (s05)
- **No SCTP / raw IP.** (s08, s10)
- **Short-lived processes** → `<UNKNOWN>` bucket (/proc scan for pid mapping, not eBPF). (s11)
- **`--total-utilization` is monotonic-cumulative but lags the transfer.** Verified live: for a paced 32 MB upload the per-process `up` climbs and plateaus at ~32 MB, but it keeps climbing for ~4 s after the transfer ends (its rolling-rate integration trails). The collector therefore polls to the ground-truth target / a plateau (the same budget every cumulative tool gets), taking the max seen, rather than a fixed short window. A sub-second *unpaced* burst is still undercounted because the per-second rate integration can't resolve it; bulk transfers are paced to a sustained multi-second rate so they measure correctly. (s20 is the unpaced-burst case.)
- **Egress attribution of short-lived upload processes is unreliable and non-deterministic.** Verified across full runs: bandwhich names the upload process from its reverse-path ACKs (small `down`) but frequently attributes the egress *bulk* (`up`) to the `<UNKNOWN>` bucket instead of the process — the generator often exits before bandwhich's /proc scan maps its egress connection. One full run named `bg_tcp_ul` with `up`≈30 MB; another dumped the same egress entirely into `<UNKNOWN>`. Downloads and longer-lived (sendfile) uploads attribute reliably. Consequence: per-process **egress** bandwidth is **flaky** run-to-run — a PASS when bandwhich attributes it, a FAIL when the bulk lands in `<UNKNOWN>`. The benchmark credits only bytes attributed to the process (the `<UNKNOWN>` bucket is excluded) and polls bandwhich on the same cumulative budget as the other tools, so these FAILs reflect attribution, not a short measurement window.
- SIGINT/SIGTERM both stop it cleanly; totals reprint every second so nothing to flush.
