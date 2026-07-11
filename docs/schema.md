# Database schema

Picosnitch stores connection logs in an SQLite database at
`/var/lib/picosnitch/picosnitch.db`. The schema is split into four
[`STRICT`](https://sqlite.org/stricttables.html) tables, with the
heavy metadata interned into side tables so the per-connection rows
stay small.

The remote SQL schema (`[database.remote]`) mirrors the same four
tables, minus the `STRICT` modifier (not all servers support it), except
the remote `executables` table dedups on an added `key_hash CHAR(64)`
column instead of a `UNIQUE(exe, name, cmdline, sha256)` constraint
(remote text columns are unbounded, breaking a raw multi-column unique
index).

## Tables

### `executables`

One row per unique (path, name, command line, sha256) tuple. The
`UNIQUE` constraint means re-executing the same binary with the same
arguments reuses the same `id`; a recompile (different sha256) or
different arguments produces a new row.

```sql
id      INTEGER PRIMARY KEY
exe     TEXT NOT NULL    -- absolute path, e.g. /usr/bin/curl
name    TEXT NOT NULL    -- /proc/<pid>/comm, e.g. curl
cmdline TEXT NOT NULL    -- argv joined with NUL -> spaces
sha256  TEXT NOT NULL    -- sha256 of the executable file itself
UNIQUE(exe, name, cmdline, sha256)
```

### `domains`

```sql
id     INTEGER PRIMARY KEY
domain TEXT NOT NULL UNIQUE
```

### `addresses`

```sql
id   INTEGER PRIMARY KEY
addr TEXT NOT NULL UNIQUE   -- IPv4 or IPv6 in canonical text form
```

### `connections`

One row per logged connection window. `events` is how many raw socket
events were collapsed into the row (controlled by
`[database].write_limit_seconds`).

```sql
contime   INTEGER NOT NULL  -- unix time, seconds
send      INTEGER NOT NULL  -- bytes sent in this window
recv      INTEGER NOT NULL  -- bytes received in this window
events    INTEGER NOT NULL  -- number of raw socket events merged
exe_id    INTEGER NOT NULL REFERENCES executables(id)
pexe_id   INTEGER NOT NULL REFERENCES executables(id)   -- parent
gpexe_id  INTEGER NOT NULL REFERENCES executables(id)   -- grandparent
uid       INTEGER NOT NULL
family    INTEGER NOT NULL  -- AF_INET=2, AF_INET6=10, 0=unknown
protocol  INTEGER NOT NULL  -- IPPROTO_* (TCP=6, UDP=17), 0=unknown
lport     INTEGER NOT NULL
rport     INTEGER NOT NULL
laddr_id  INTEGER NOT NULL REFERENCES addresses(id)
raddr_id  INTEGER NOT NULL REFERENCES addresses(id)
domain_id INTEGER NOT NULL REFERENCES domains(id)
netns     INTEGER NOT NULL  -- socket's network namespace inode
```

## Indexes

```sql
CREATE INDEX idx_contime          ON connections(contime);
CREATE INDEX idx_exe_id_contime   ON connections(exe_id,   contime);
CREATE INDEX idx_pexe_id_contime  ON connections(pexe_id,  contime);
CREATE INDEX idx_gpexe_id_contime ON connections(gpexe_id, contime);
```

The composite indexes cover the common "what did this executable do
in the last hour/day/week" query in either direction (by exe, by
parent, by grandparent) without paying the cost of indexing every
column individually.

## Example queries

Read-only browsing is what `picosnitch tui` and `picosnitch webui`
already do, but the schema is intentionally easy to query by hand.

Top 10 executables by bytes received in the last 24 hours:

```sql
SELECT e.name, e.exe, SUM(c.recv) AS bytes_in
FROM connections c
JOIN executables e ON e.id = c.exe_id
WHERE c.contime >= unixepoch('now', '-1 day')
GROUP BY c.exe_id
ORDER BY bytes_in DESC
LIMIT 10;
```

Every distinct (executable, remote domain) pair seen this week:

```sql
SELECT DISTINCT e.name, e.exe, d.domain
FROM connections c
JOIN executables e ON e.id = c.exe_id
JOIN domains     d ON d.id = c.domain_id
WHERE c.contime >= unixepoch('now', '-7 days')
ORDER BY e.name, d.domain;
```

All connections opened by a process whose grandparent was the user's
shell (useful for spotting what a script you ran actually contacted):

```sql
SELECT datetime(c.contime, 'unixepoch') AS t,
       e.name, d.domain, c.rport
FROM connections c
JOIN executables e  ON e.id  = c.exe_id
JOIN executables gp ON gp.id = c.gpexe_id
JOIN domains     d  ON d.id  = c.domain_id
WHERE gp.name IN ('bash', 'zsh', 'fish')
ORDER BY c.contime DESC;
```

## CSV log (`conn.log`)

If `[database].text_log = true`, picosnitch also writes a flat CSV at
`/var/log/picosnitch/conn.log` with these fields per row (commas,
newlines, carriage returns, and NUL bytes are stripped from values):

```
entry time, sent bytes, received bytes, event count,
executable path, process name, cmdline, sha256,
parent executable, parent name, parent cmdline, parent sha256,
grandparent executable, grandparent name, grandparent cmdline, grandparent sha256,
user id, address family, protocol, local port, remote port,
local address, remote address, domain, network namespace
```
