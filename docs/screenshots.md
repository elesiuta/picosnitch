# Screenshots

A tour of every UI picosnitch ships with.

## Web UI

The web UI runs locally (`picosnitch webui`) and reads the same SQLite
log shown elsewhere. It paints a stacked bandwidth chart, a sortable
top-contributors table, and a per-axis breakdown sidebar.

### Overview

The default landing tab. Bandwidth over time, grouped by executable by
default, with top contributors below the chart.

[![Overview, last hour](https://github.com/elesiuta/picosnitch/releases/latest/download/webui-overview-1h.png){ width="100%" }](https://github.com/elesiuta/picosnitch/releases/latest/download/webui-overview-1h.png)

[![Overview, last day](https://github.com/elesiuta/picosnitch/releases/latest/download/webui-overview-1d.png){ width="100%" }](https://github.com/elesiuta/picosnitch/releases/latest/download/webui-overview-1d.png)

### Light theme

Themes follow the system preference. Both palettes use the same chart
and tables.

[![Overview, light theme](https://github.com/elesiuta/picosnitch/releases/latest/download/webui-overview-1d-light.png){ width="100%" }](https://github.com/elesiuta/picosnitch/releases/latest/download/webui-overview-1d-light.png)

### Group by executable

Pick any of the dimensions in the sidebar to re-bucket the chart and
table. Grouping by executable shows which binaries are responsible
for the bytes on the wire, with a drill-down panel on the right.

[![Grouped by executable](https://github.com/elesiuta/picosnitch/releases/latest/download/webui-by-exe-1d.png){ width="100%" }](https://github.com/elesiuta/picosnitch/releases/latest/download/webui-by-exe-1d.png)

### Group by domain

The same view, regrouped by DNS name.

[![Grouped by domain](https://github.com/elesiuta/picosnitch/releases/latest/download/webui-by-domain-1d.png){ width="100%" }](https://github.com/elesiuta/picosnitch/releases/latest/download/webui-by-domain-1d.png)

### Drill-down on a single executable

Filtering by an executable opens a detail panel with byte counters,
plus by-UID, by-network-namespace, by-domain, and by-address
breakdowns for just that binary.

[![Drilled in on Web Content](https://github.com/elesiuta/picosnitch/releases/latest/download/webui-filter-web-content.png){ width="100%" }](https://github.com/elesiuta/picosnitch/releases/latest/download/webui-filter-web-content.png)

### Live tab

The Live tab streams new events from the daemon as they happen, the
same source `picosnitch top` uses.

[![Live tab](https://github.com/elesiuta/picosnitch/releases/latest/download/webui-live.png){ width="100%" }](https://github.com/elesiuta/picosnitch/releases/latest/download/webui-live.png)

---

## Terminal UI

`picosnitch tui` is a read-only curses view of the same database.
Useful over SSH, on headless boxes, or when you just want a quick
look without spinning up a browser.

### Group by process name

[![By process name](https://github.com/elesiuta/picosnitch/releases/latest/download/tui-process-names.png){ width="100%" }](https://github.com/elesiuta/picosnitch/releases/latest/download/tui-process-names.png)

### Group by parent

Same data, regrouped by the parent process of each connection.

[![By parent](https://github.com/elesiuta/picosnitch/releases/latest/download/tui-parent-names.png){ width="100%" }](https://github.com/elesiuta/picosnitch/releases/latest/download/tui-parent-names.png)

### Group by domain

[![By domain](https://github.com/elesiuta/picosnitch/releases/latest/download/tui-domains.png){ width="100%" }](https://github.com/elesiuta/picosnitch/releases/latest/download/tui-domains.png)

### Group by remote address

GeoIP country codes are shown next to each remote address (using the
DB-IP Country Lite database, refreshed monthly).

[![By remote address](https://github.com/elesiuta/picosnitch/releases/latest/download/tui-remote-addresses.png){ width="100%" }](https://github.com/elesiuta/picosnitch/releases/latest/download/tui-remote-addresses.png)

### Find filter

Press `/` to filter the current grouping by substring match.

[![Find filter](https://github.com/elesiuta/picosnitch/releases/latest/download/tui-find.png){ width="100%" }](https://github.com/elesiuta/picosnitch/releases/latest/download/tui-find.png)

### Live tab

The TUI's Live tab mirrors `picosnitch top`.

[![TUI live tab](https://github.com/elesiuta/picosnitch/releases/latest/download/tui-live.png){ width="100%" }](https://github.com/elesiuta/picosnitch/releases/latest/download/tui-live.png)

---

## Live event feed (`picosnitch top`)

`picosnitch top` streams events from the running daemon over a local
socket. Requires root. Useful for catching what a specific command or
script actually does on the network.

### Default view

[![top default](https://github.com/elesiuta/picosnitch/releases/latest/download/top-default.png){ width="100%" }](https://github.com/elesiuta/picosnitch/releases/latest/download/top-default.png)

### Sorted by received bytes

[![top sorted by recv](https://github.com/elesiuta/picosnitch/releases/latest/download/top-sort-recv.png){ width="100%" }](https://github.com/elesiuta/picosnitch/releases/latest/download/top-sort-recv.png)

### Paused

[![top paused](https://github.com/elesiuta/picosnitch/releases/latest/download/top-paused.png){ width="100%" }](https://github.com/elesiuta/picosnitch/releases/latest/download/top-paused.png)

### Help overlay

[![top help overlay](https://github.com/elesiuta/picosnitch/releases/latest/download/top-help.png){ width="100%" }](https://github.com/elesiuta/picosnitch/releases/latest/download/top-help.png)
