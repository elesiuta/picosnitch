# Little Snitch for Linux + additional/excluded tools

## Little Snitch for Linux
- **Pinned version:** 1.0.9 (2026-05-11). Install `.deb`:
  `https://obdev.at/downloads/littlesnitch-linux/littlesnitch_1.0.9_amd64.deb` (static musl `.tar.gz` also available).
- **Requires** kernel 6.12+ with BTF (same floor as picosnitch). eBPF-based; daemon + **web UI at http://localhost:3031**.
- Does **per-application bandwidth + firewall** (obdev call it a privacy tool, "not a security tool").
- **Extraction — reverse-engineered from the web UI (confirmed working on this box):** the `.deb` installs cleanly (`/usr/bin/littlesnitch`, 16 MB); the daemon runs and listens on **127.0.0.1:3031**. There is no documented CLI/JSON export (`littlesnitch --help` has only `--daemon`/`--hash-password`/`--version`/sandbox flags), but the SPA at `:3031` drives itself over a **WebSocket, `ws://127.0.0.1:3031/stream`**, which pushes JSON `insertConnectionRows` / `updateConnectionRows` messages: connection rows keyed by rowId with a `title` (process name) and cumulative `statistics.bytesSent/bytesReceived`. The harness reads that socket directly (a minimal stdlib client — no third-party dep). The `statistics` block is byte-exact; the `trafficEvents` messages are only approximate (don't use them).
- **Attribution gotcha:** little-snitch attributes traffic to the **top-level "responsible" application**, not the leaf process — a synthetic generator launched by the test harness gets folded into the ancestor (verified: a 20 MiB transfer was attributed to the launching session's top-level process, not the generator). To get a distinct row, each generator is launched as its own **detached transient systemd service** (`systemd-run --pipe --collect`), which makes it a top-level app titled by the exe name. Also aggregates by name over persistent history (`/var/lib/littlesnitch/connections.sqlite`), so the harness clears that file per run.
- **Result:** byte-exact per-process on TCP; ICMP detection was inconsistent in the matrix (1/5 trials) and its ICMP byte counts are far under the reference.

## Conflation note
"Little Snitch for Linux" pre-April-2026 references almost always meant **OpenSnitch** (self-described "Little Snitch–like" firewall).
