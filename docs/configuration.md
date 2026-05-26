# Configuration

Config is stored at `/etc/picosnitch/config.toml` and is created with
sensible defaults on first run. Restart picosnitch for changes to take
effect:

```sh
sudo systemctl restart picosnitch
```

## `config.toml`

The block below is included verbatim from the project README.

--8<-- "README.md:config-toml"

## Environment variables

| Variable | Used by | Purpose |
| --- | --- | --- |
| `PICOSNITCH_HOST` | `picosnitch webui` | Override the web UI bind address (default `127.0.0.1`). |
| `PICOSNITCH_PORT` | `picosnitch webui` | Override the web UI port (default `5100`). |
| `SUDO_UID` | daemon | Used as the default `[desktop].user` for notifications. |

## Remote logging

`[database.remote]` ships every connection to a MariaDB, MySQL, or
PostgreSQL server in addition to the local SQLite log. Install the
optional drivers with the `[sql]` extra:

```sh
sudo pipx install 'picosnitch[sql]' --global
```

Picosnitch only ever issues `INSERT` against the remote (no retention,
no garbage collection), so it is intended as an
[off-system copy of your logs](https://en.wikipedia.org/wiki/Host-based_intrusion_detection_system#Protecting_the_HIDS).
Grant the daemon's database user `INSERT` only to prevent an adversary
on the monitored host from deleting picosnitch's off-system logs.

The remote schema mirrors the local SQLite layout
([see schema](schema.md)). Only the `connections` table name is
configurable (via `connections_table`), which lets multiple hosts share
one server with their own `connections_<host>` table each while reusing
the shared `executables` / `domains` / `addresses` reference tables.

Example, ship logs to a MariaDB server with a per-host table:

```toml
[database.remote]
client = "mariadb"
host = "logs.example.internal"
port = 3306
user = "picosnitch"
password = "..."
database = "picosnitch"
connections_table = "connections_workstation1"
```
