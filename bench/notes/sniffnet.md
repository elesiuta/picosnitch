# Sniffnet — benchmark notes

- **Pinned version:** v1.5.0 (2026-04-14). Install the `.deb`; runtime deps: libpcap, GTK3, ALSA, fontconfig.
- Desktop GUI app (Rust/iced). No headless mode, no CLI report, no web UI.
- v1.5 attributes traffic to processes only in the live GUI; no per-process data is written to disk. The only file export is a PCAP (raw packets, no process field).

## How it is benchmarked here
- Run headless under an explicit **Xvfb** display with `ICED_BACKEND=tiny-skia` (pure-CPU software renderer) and `--adapter vbench0` to auto-start capture. Needs `libxkbcommon-x11-0` or it panics at startup (`libxkbcommon-x11.so could not be loaded`).
- Since there is **no export**, per-process data is read by **OCR (tesseract) of the Overview "Program" panel**: screenshot the rendered window, OCR it, fuzzy-match our unique generator name, and read its byte figure.
- A parallel `tcpdump` on the same interface provides the wire-level reference and a **flow-level fallback** for scenarios where OCR can't attribute (e.g. ICMP).

## OCR extraction limitations
- **Coarse bytes:** sniffnet rounds figures to ~2 significant figures ("35 MB"); within ±10% on TCP for round bulk transfers, error grows for non-round sizes.
- **Name misreads:** OCR misreads process names ("bg_ocr_probe" → "ba.ocr_probe"), so matching is approximate; a miss falls back to flow level (PARTIAL).
- **One figure per program:** sniffnet shows a per-program *total*, not a sent/recv split, so the total is assigned to the scenario's tested direction.
