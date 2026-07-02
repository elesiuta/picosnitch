# picosnitch

**Per-executable network bandwidth monitoring for Linux.**

Picosnitch is a small userspace daemon built on
[BPF](https://ebpf.io/) and
[fanotify](https://man7.org/linux/man-pages/man7/fanotify.7.html).
It notifies you when a new program connects to the network or when one
is modified on disk, and keeps a per-executable log of every
connection, with sent/received bytes, hashes, parents, domains, ports,
and users.

[:material-github: GitHub](https://github.com/elesiuta/picosnitch){ .md-button .md-button--primary }
[:simple-pypi: PyPI](https://pypi.org/project/picosnitch/){ .md-button }
[:material-package-variant: Packages](https://repology.org/project/picosnitch/versions){ .md-button }

---

## Web UI

<video controls muted playsinline loop preload="metadata" width="100%"
       src="screenshots/out/web_ui.webm"
       poster="screenshots/out/webui-filter-web-content.png"></video>

Bandwidth and connection counts broken down by executable, parent,
domain, port, or user, over a configurable time range. Light and dark
themes follow your system preference.

```sh
picosnitch webui
# http://localhost:5100  (override with PICOSNITCH_HOST / PICOSNITCH_PORT)
```

---

## Terminal UI

<video controls muted playsinline loop preload="metadata" width="100%"
       src="screenshots/out/tui.webm"
       poster="screenshots/out/tui-process-names.png"></video>

A curses-based read-only view of the same database, useful over SSH or
on headless boxes. Filter by executable, parent, command line, domain,
address, or user; GeoIP country codes are shown next to remote
addresses.

```sh
picosnitch tui
```

---

## Live event feed

<a href="screenshots/out/top-default.png">
  <img src="screenshots/out/top-default.png"
       alt="picosnitch top live feed" width="100%">
</a>

`picosnitch top` streams events directly from the running daemon:
every new connection as it happens, with cumulative
sent/received counters and per-row process detail. Requires root
because it reads the daemon's local socket.

```sh
sudo picosnitch top
```

---

## Install

The recommended install is system-wide via
[pipx](https://pipx.pypa.io/stable/how-to/install-pipx/)
(requires pipx >= 1.5.0):

```sh
sudo pipx install picosnitch --global
sudo picosnitch systemd
sudo systemctl enable --now picosnitch
```

See [configuration](configuration.md) for the full TOML reference,
[how it works](how-it-works.md) for the architecture overview, the
[database schema](schema.md) if you want to query the SQLite log
directly, and [more screenshots](screenshots.md) of every UI variant.
For distribution-packaged builds, see
[Repology](https://repology.org/project/picosnitch/versions).
