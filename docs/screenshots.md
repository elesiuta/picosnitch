# Screenshots

A tour of every UI picosnitch ships with.

## Web UI

The web UI runs locally (`picosnitch webui`) and reads the same SQLite
log shown elsewhere. It paints a stacked bandwidth chart, a sortable
top-contributors table, and a per-axis breakdown sidebar.

<video controls muted playsinline loop preload="metadata" width="100%"
       src="out/web_ui.webm"
       poster="out/webui-overview-1d.png"></video>

### Overview

The default landing tab. Bandwidth over time, grouped by executable by
default, with top contributors below the chart.

![Overview, last hour](screenshots/out/webui-overview-1h.png){ width="100%" }

![Overview, last day](screenshots/out/webui-overview-1d.png){ width="100%" }

### Light theme

Themes follow the system preference. Both palettes use the same chart
and tables.

![Overview, light theme](screenshots/out/webui-overview-1d-light.png){ width="100%" }

### Group by executable

Pick any of the dimensions in the sidebar to re-bucket the chart and
table. Grouping by executable shows which binaries are responsible
for the bytes on the wire, with a drill-down panel on the right.

![Grouped by executable](screenshots/out/webui-by-exe-1d.png){ width="100%" }

### Group by domain

The same view, regrouped by DNS name.

![Grouped by domain](screenshots/out/webui-by-domain-1d.png){ width="100%" }

### Drill-down on a single executable

Filtering by an executable opens a detail panel with byte counters,
plus by-UID, by-network-namespace, by-domain, and by-address
breakdowns for just that binary.

![Drilled in on Web Content](screenshots/out/webui-filter-web-content.png){ width="100%" }

### Live tab

The Live tab streams new events from the daemon as they happen, the
same source `picosnitch top` uses.

![Live tab](screenshots/out/webui-live.png){ width="100%" }

---

## Terminal UI

`picosnitch tui` is a curses view of the same database, useful over
SSH, on headless boxes, or when you just want a quick look without
spinning up a browser.

<video controls muted playsinline loop preload="metadata" width="100%"
       src="out/tui.webm"
       poster="out/tui-process-names.png"></video>

### Group by process name

![By process name](screenshots/out/tui-process-names.png){ width="100%" }

### Group by parent

Same data, regrouped by the parent process of each connection.

![By parent](screenshots/out/tui-parent-names.png){ width="100%" }

### Group by domain

![By domain](screenshots/out/tui-domains.png){ width="100%" }

### Group by remote address

GeoIP country codes are shown next to each remote address (using the
DB-IP Country Lite database, refreshed monthly).

![By remote address](screenshots/out/tui-remote-addresses.png){ width="100%" }

### Find filter

Press `/` to filter the current grouping by substring match.

![Find filter](screenshots/out/tui-find.png){ width="100%" }

### Live tab

The TUI's Live tab mirrors `picosnitch top`.

![TUI live tab](screenshots/out/tui-live.png){ width="100%" }

---

## Live event feed (`picosnitch top`)

`picosnitch top` streams events from the running daemon over a local
socket. Requires root. Useful for catching what a specific command or
script actually does on the network.

<video controls muted playsinline loop preload="metadata" width="100%"
       src="out/top.webm"
       poster="out/top-default.png"></video>

### Default view

![top default](screenshots/out/top-default.png){ width="100%" }

### Sorted by received bytes

![top sorted by recv](screenshots/out/top-sort-recv.png){ width="100%" }

### Paused

![top paused](screenshots/out/top-paused.png){ width="100%" }

### Help overlay

![top help overlay](screenshots/out/top-help.png){ width="100%" }
