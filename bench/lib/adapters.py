"""Per-tool adapters. Each wraps one monitor with a uniform interface:
install() / start() / pre_trial() / collect(gt) / stop().

The runner runs as root, so sh() calls here already have privileges.

Collection model: every monitor runs continuously for its whole session. For
cumulative-total tools (nethogs, bandwhich) we snapshot per-process totals in
pre_trial() and take the delta in collect(). For event/log tools (picosnitch
rowid, opensnitch journald, sniffnet pcap, bcc) we window by the trial's exe /
time / rowid. Failures degrade to a noted Observation rather than aborting.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import subprocess
import time
import urllib.request
from pathlib import Path

from harness import BENCH, GT, Observation, sh

DL = BENCH / "downloads"
DL.mkdir(exist_ok=True)


def _download(url, dest):
    if Path(dest).exists() and Path(dest).stat().st_size > 0:
        return dest
    urllib.request.urlretrieve(url, dest)
    return dest


class ToolAdapter:
    name = "base"
    layer = "socket"  # socket | wire  (which ground-truth reference to score against)
    does_bandwidth = True
    does_attribution = True
    settle = 2.0  # seconds to wait after a trial before collecting
    gen_prefix = []  # optional wrapper the runner applies to generator launches
    # The version actually running is read from the installed tool after install()
    # and recorded with the results, so reports state observed versions rather than
    # intended ones. SOURCE distinguishes a version this harness pins (built or
    # downloaded at a fixed tag) from a distro package, whose version is whatever
    # the archive currently ships and is only recorded.
    VERSION_CMD = ""
    VERSION_SOURCE = ""

    def __init__(self, sess: Path):
        self.sess = sess
        self.sess.mkdir(parents=True, exist_ok=True)
        self.proc = None

    def version(self) -> str:
        """Observed version of the installed tool ('' if it cannot be read)."""
        if not self.VERSION_CMD:
            return ""
        r = sh(self.VERSION_CMD)
        out = (r.stdout or "") + (r.stderr or "")
        m = re.search(r"\d+\.\d+(\.\d+)*(-\S+)?", out)
        return m.group(0) if m else ""

    # lifecycle ---------------------------------------------------------------
    def install(self): ...

    def start(self): ...

    def pre_trial(self):
        self._snap = {}

    def collect(self, gt: GT) -> Observation:
        raise NotImplementedError

    # Shared cumulative-bandwidth polling model (nethogs, bandwhich; picosnitch's
    # collect() applies the same budget to its database reads). Every monotonic-
    # cumulative tool gets the SAME budget so none is advantaged by a longer
    # window: poll until the known ground-truth amount is reached (fast path),
    # the value plateaus, or the deadline. Returns the MAX seen for each
    # direction, so a transient dip or a premature plateau can never lose a value
    # the tool did report. `sample` returns (sent, recv, names, attr, unknown).
    POLL = 0.6
    STABLE_HITS = 25  # ~15s of no growth -> settled
    ZERO_HITS = 25  # ~15s of nothing -> genuinely zero (must match STABLE_HITS)
    DEADLINE_HITS = 90  # ~54s hard cap

    def _poll_cumulative(self, sample, target):
        best_s = best_r = 0.0
        names, attributed, unknown = [], False, False
        prev, stable, zero = None, 0, 0
        for _ in range(self.DEADLINE_HITS):
            s, r, nm, attr, unk = sample()
            best_s, best_r = max(best_s, s), max(best_r, r)
            if nm:
                names = nm
            attributed = attributed or attr
            unknown = unknown or unk
            total = best_s + best_r
            if target > 0 and total >= target:
                break  # captured the known amount -> done fast
            if total == 0:
                zero += 1
                if zero >= self.ZERO_HITS:
                    break
            cur = (round(best_s), round(best_r))
            if cur == prev and total > 0:
                stable += 1
                if stable >= self.STABLE_HITS:
                    break
            else:
                stable = 0
            prev = cur
            time.sleep(self.POLL)
        return best_s, best_r, names, attributed, unknown

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except Exception:
                self.proc.kill()
        self.proc = None

    def pids(self):
        """Root PID(s) of this tool's process tree, for the resource profiler.
        Default: the subprocess handle(s) the adapter launched. Daemon tools
        (their process is not our child) override with the service MainPID."""
        out = []
        for p in (getattr(self, "proc", None), getattr(self, "proc2", None)):
            if p is not None and p.poll() is None:
                out.append(p.pid)
        return out


def _systemd_mainpid(service):
    """MainPID of a systemd service as a single-element list (empty if none)."""
    r = sh(f"systemctl show -p MainPID --value {service}")
    try:
        pid = int(r.stdout.strip())
        return [pid] if pid > 0 else []
    except (ValueError, AttributeError):
        return []


# --------------------------------------------------------------------------- #
# picosnitch: installed from PyPI via pipx, NOT the source tree
# --------------------------------------------------------------------------- #
class Picosnitch(ToolAdapter):
    name = "picosnitch"
    VERSION = "2.2.1"
    VERSION_CMD = "picosnitch version"
    VERSION_SOURCE = "pinned (PyPI via pipx)"
    layer = "socket"
    settle = 2.0  # small; collect() polls until the DB flush stabilizes
    DB = "/var/lib/picosnitch/picosnitch.db"

    def install(self):
        # config first, unconditionally: local DB, fine time resolution, no
        # notifications / geoip download -- a pre-existing install must not run
        # the benchmark under different settings.
        Path("/etc/picosnitch").mkdir(parents=True, exist_ok=True)
        Path("/etc/picosnitch/config.toml").write_text(
            "[database]\nenabled = true\nretention_days = 30\n"
            "write_limit_seconds = 1\ntext_log = false\n\n"
            "[log]\naddresses = true\ncommands = true\nports = true\n\n"
            "[desktop]\nnotifications = false\ngeoip_lookup = false\n\n"
            "[monitoring]\nevery_exe = false\n"
        )
        # early return only for the PINNED version (any other install would be
        # silently benchmarked while the report claims the pinned one)
        if self.version() == self.VERSION and Path("/usr/local/bin/picosnitch").exists():
            return
        if sh("command -v pipx").returncode != 0:
            sh("apt-get install -y pipx")
        r = sh(f"pipx install 'picosnitch=={self.VERSION}' --global", timeout=600)
        if r.returncode != 0:
            raise RuntimeError(f"picosnitch install failed: {r.stderr}\n{r.stdout}")

    def start(self):
        # Fresh DB each run so this run's rows are unambiguous (names repeat
        # across runs, and a connection can split across hash/no-hash exe rows).
        sh("systemctl stop picosnitch")
        sh(f"rm -f {self.DB}")
        sh("picosnitch systemd")  # writes the unit
        sh("systemctl daemon-reload")
        sh("systemctl restart picosnitch")
        # wait for the daemon + DB to come up
        for _ in range(40):
            if Path(self.DB).exists() and sh("systemctl is-active --quiet picosnitch").returncode == 0:
                break
            time.sleep(0.5)
        time.sleep(3)

    def _maxrowid(self):
        try:
            con = sqlite3.connect(f"file:{self.DB}?mode=ro", uri=True, timeout=5)
            r = con.execute("SELECT COALESCE(MAX(rowid),0) FROM connections").fetchone()[0]
            con.close()
            return r
        except Exception:
            return 0

    def pre_trial(self):
        self._snap = {"rowid": self._maxrowid()}

    def _query(self, snap, exe):
        con = sqlite3.connect(f"file:{self.DB}?mode=ro", uri=True, timeout=10)
        rows = con.execute("SELECT e.name, e.exe, SUM(c.send), SUM(c.recv) FROM connections c JOIN executables e ON c.exe_id=e.id WHERE c.rowid > ? GROUP BY e.id", (snap,)).fetchall()
        con.close()
        sent = recv = 0
        names, attributed = [], False
        for nm, exe_, s, r in rows:
            if exe in (nm or "") or exe in (exe_ or ""):
                sent += s or 0
                recv += r or 0
                names.append(nm)
                attributed = True
        return sent, recv, names, attributed

    def collect(self, gt: GT) -> Observation:
        snap = self._snap["rowid"]
        # picosnitch flushes a connection's bytes across MULTIPLE executable rows
        # (e.g. a hash-pending row then the hashed row) over several seconds, so
        # the sum can look "stable" mid-flush and a single stable read can miss a
        # late-flushing row. Wait until it has plainly captured everything
        # (reached ~the known amount, since its hooks count app bytes) OR has
        # held steady over a long window OR is genuinely zero.
        target = 0.97 * (gt.app_sent + gt.app_recv)
        prev = None
        stable = zero = 0
        sent = recv = 0
        names, attributed = [], False
        # Poll cadence + thresholds. picosnitch eventually reports the full byte
        # count, but its flush-to-SQLite latency after a transfer is bursty and long
        # (measured up to ~10s on a full-duplex trial: the writer pipeline plus
        # first-sight executable hashing). The target fast-path below breaks in a
        # few seconds once the known amount is on disk, so the "settled" plateau
        # must OUT-WAIT that flush tail -- a short (~5s) plateau snapshots a slow
        # trial mid-flush and spuriously undercounts. ~15s comfortably clears the
        # observed tail while the fast-path keeps good trials quick.
        POLL = 0.6
        STABLE_HITS = 25  # ~15s of no change -> flush genuinely settled
        ZERO_HITS = 25  # ~15s of NOTHING -> genuinely zero (e.g. AF_PACKET). Must
        # match STABLE_HITS: a slow flush that has not written any
        # row yet must not be mistaken for a genuine zero.
        DEADLINE_HITS = 90  # ~54s hard cap (headroom above the two ~15s windows)
        for _ in range(DEADLINE_HITS):
            try:
                sent, recv, names, attributed = self._query(snap, gt.exe)
            except Exception as e:
                return Observation(note=f"db error: {e}")
            total = sent + recv
            if target > 0 and total >= target:
                break  # captured ~everything -> done fast
            if total == 0:
                zero += 1
                if zero >= ZERO_HITS:
                    break
            cur = (sent, recv)
            if cur == prev and total > 0:
                stable += 1
                if stable >= STABLE_HITS:  # flush settled below target -> genuine undercount
                    break
            else:
                stable = 0
            prev = cur
            time.sleep(POLL)
        return Observation(flow_detected=attributed, proc_attributed=attributed, names=names, sent=sent, recv=recv)

    def pids(self):
        return _systemd_mainpid("picosnitch")

    def stop(self):
        sh("systemctl stop picosnitch")


# --------------------------------------------------------------------------- #
# nethogs: built from source at the pinned tag
# --------------------------------------------------------------------------- #
class Nethogs(ToolAdapter):
    name = "nethogs"
    VERSION_CMD = "/usr/local/sbin/nethogs -V 2>&1"
    VERSION_SOURCE = "pinned (built from source tag)"
    layer = "wire"
    settle = 2.5

    VERSION = "0.9.0"

    def install(self):
        if f"version {self.VERSION}" in sh("/usr/local/sbin/nethogs -V 2>&1").stdout:
            return
        sh("apt-get install -y build-essential libpcap-dev libncurses-dev git")
        src = DL / "nethogs"
        if not src.exists():
            sh(f"git clone https://github.com/raboof/nethogs {src}", timeout=300)
        sh(f"git -C {src} fetch --tags", timeout=300)
        sh(f"git -C {src} checkout v{self.VERSION}")
        r = sh(f"make -C {src} clean; make -C {src} && make -C {src} install", timeout=600)
        if f"version {self.VERSION}" not in sh("/usr/local/sbin/nethogs -V 2>&1").stdout:
            raise RuntimeError(f"nethogs {self.VERSION} build failed: {r.stderr[-800:]}")

    def start(self):
        # -t trace, -C include UDP, -v2 cumulative bytes, -a include loopback,
        # -d1 refresh 1s. Continuous; parse the growing log. No shell, so self.proc
        # IS nethogs (killing it directly, not orphaning it behind a shell).
        self.log = self.sess / "nethogs.log"
        self.proc = subprocess.Popen(["/usr/local/sbin/nethogs", "-t", "-C", "-v", "2", "-a", "-d", "1", "vbench0", "lo"], stdout=open(self.log, "w"), stderr=subprocess.STDOUT)
        time.sleep(3)

    def stop(self):
        sh("pkill -INT -x nethogs")
        time.sleep(1)
        super().stop()
        sh("pkill -9 -x nethogs")

    def _cumulative(self):
        """name-substr -> (sent,recv) from the latest values (max, monotonic)."""
        best = {}
        try:
            for line in open(self.log, errors="replace"):
                if "\t" not in line:
                    continue
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 3:
                    continue
                key = parts[0]
                try:
                    s = float(parts[1])
                    r = float(parts[2])
                except ValueError:
                    continue
                # key = <name>/<pid>/<uid>
                m = key.rsplit("/", 2)
                nm = m[0] if len(m) == 3 else key
                cur = best.get(nm, (0.0, 0.0))
                best[nm] = (max(cur[0], s), max(cur[1], r))
        except FileNotFoundError:
            pass
        return best

    def pre_trial(self):
        self._snap = self._cumulative()

    def _delta(self, gt):
        now = self._cumulative()
        a_s = a_r = u_s = u_r = 0.0
        names, attributed, unknown = [], False, False
        for nm, (s, r) in now.items():
            ps, pr = self._snap.get(nm, (0.0, 0.0))
            ds, dr = s - ps, r - pr
            if ds < 1 and dr < 1:
                continue
            if gt.exe in nm:
                a_s += ds
                a_r += dr
                names.append(nm)
                attributed = True
            elif "unknown" in nm.lower():
                u_s += ds
                u_r += dr
                unknown = True
        # Score THIS process's bytes only: the attributed delta when we have it, else
        # the unknown bucket -- never both, so background unattributed traffic on the
        # monitored interface can't inflate an otherwise-clean measurement.
        if attributed:
            return a_s, a_r, names, True, unknown
        return u_s, u_r, names, False, unknown

    def collect(self, gt: GT) -> Observation:
        # nethogs' -v2 totals are monotonic-cumulative; use the shared target/plateau
        # poll so it gets the same collection budget as the other cumulative tools.
        target = 0.97 * (gt.app_sent + gt.app_recv)
        sent, recv, names, attributed, unknown = self._poll_cumulative(lambda: self._delta(gt), target)
        detected = attributed or unknown
        note = "" if attributed else ("bucketed as unknown" if unknown else "not detected")
        return Observation(flow_detected=detected, proc_attributed=attributed, names=names, sent=int(sent), recv=int(recv), note=note)


# --------------------------------------------------------------------------- #
# bandwhich: static musl release binary
# --------------------------------------------------------------------------- #
class Bandwhich(ToolAdapter):
    name = "bandwhich"
    VERSION_CMD = "bandwhich --version"
    VERSION_SOURCE = "pinned (release binary)"
    layer = "wire"
    settle = 2.5
    VERSION = "0.23.1"
    URL = f"https://github.com/imsnif/bandwhich/releases/download/v{VERSION}/bandwhich-v{VERSION}-x86_64-unknown-linux-musl.tar.gz"

    def install(self):
        if self.version() == self.VERSION:
            return
        tgz = _download(self.URL, DL / f"bandwhich-{self.VERSION}.tar.gz")
        sh(f"tar xzf {tgz} -C {DL}")
        sh(f"install -m0755 {DL}/bandwhich /usr/local/bin/bandwhich")
        if self.version() != self.VERSION:
            raise RuntimeError(f"bandwhich {self.VERSION} install failed, found {self.version() or 'nothing'}")

    def start(self):
        self.log = self.sess / "bandwhich.log"
        self.proc = subprocess.Popen(["/usr/local/bin/bandwhich", "--raw", "--total-utilization", "--no-resolve"], stdout=open(self.log, "w"), stderr=subprocess.STDOUT)
        time.sleep(3)

    def stop(self):
        sh("pkill -INT -x bandwhich")
        time.sleep(0.5)
        super().stop()
        sh("pkill -9 -x bandwhich")

    _re = re.compile(r'process: <\d+> "(.*?)" up/down Bps: (\d+)/(\d+)')

    def _cumulative(self):
        best = {}
        try:
            for line in open(self.log, errors="replace"):
                m = self._re.search(line)
                if not m:
                    continue
                nm, s, r = m.group(1), int(m.group(2)), int(m.group(3))
                cur = best.get(nm, (0, 0))
                best[nm] = (max(cur[0], s), max(cur[1], r))
        except FileNotFoundError:
            pass
        return best

    def pre_trial(self):
        self._snap = self._cumulative()

    def _delta(self, gt):
        now = self._cumulative()
        a_s = a_r = u_s = u_r = 0
        names, attributed, unknown = [], False, False
        for nm, (s, r) in now.items():
            ps, pr = self._snap.get(nm, (0, 0))
            ds, dr = s - ps, r - pr
            if ds < 1 and dr < 1:
                continue
            if gt.exe in nm:
                a_s += ds
                a_r += dr
                names.append(nm)
                attributed = True
            elif "UNKNOWN" in nm.upper():
                u_s += ds
                u_r += dr
                unknown = True
        # Score THIS process's bytes: the attributed delta when we have it, else the
        # <UNKNOWN> bucket -- never both, so background unattributed traffic on the
        # monitored interface can't inflate an otherwise-clean measurement.
        if attributed:
            return a_s, a_r, names, True, unknown
        return u_s, u_r, names, False, unknown

    def collect(self, gt: GT) -> Observation:
        # bandwhich's --total-utilization value is monotonic-cumulative but its
        # egress attribution to short-lived processes can lag well past a short
        # window; the shared target/plateau poll waits it out and takes the max.
        target = 0.97 * (gt.app_sent + gt.app_recv)
        sent, recv, names, attributed, unknown = self._poll_cumulative(lambda: self._delta(gt), target)
        detected = attributed or unknown
        note = "" if attributed else ("bucketed as <UNKNOWN>" if unknown else "not detected")
        return Observation(flow_detected=detected, proc_attributed=attributed, names=names, sent=sent, recv=recv, note=note)


# --------------------------------------------------------------------------- #
# opensnitch: detection only; connection log read from journald
# --------------------------------------------------------------------------- #
class OpenSnitch(ToolAdapter):
    name = "opensnitch"
    VERSION_CMD = "dpkg-query -W -f '${Version}' opensnitch"
    VERSION_SOURCE = "pinned (release .deb)"
    layer = "socket"
    does_bandwidth = False  # firewall/detector: no byte accounting
    does_attribution = True
    settle = 2.0
    DEB = "https://github.com/evilsocket/opensnitch/releases/download/v1.8.0/opensnitch_1.8.0-1_amd64.deb"

    def install(self):
        if sh("dpkg -s opensnitch 2>/dev/null | grep -q '1.8.0'").returncode != 0:
            deb = _download(self.DEB, DL / "opensnitch.deb")
            sh(f"apt-get install -y {deb}", timeout=600)
        # syslog logger; the daemon's own bracketed CONNECTION lines land
        # in journald under identifier "opensnitch" (the json Format/Tag here are
        # not honored) -- collect() parses those. Default action allow (non-blocking).
        cfg = json.loads(Path("/etc/opensnitchd/default-config.json").read_text())
        cfg["DefaultAction"] = "allow"
        cfg.setdefault("Server", {})
        cfg["Server"]["Loggers"] = [{"Name": "syslog", "Server": "", "Protocol": "", "Format": "json", "Tag": "opensnitch", "Workers": 1}]
        # eBPF .o may not match kernel 7.0 — fall back to /proc scanning if so
        cfg["ProcMonitorMethod"] = "ebpf"
        Path("/etc/opensnitchd/default-config.json").write_text(json.dumps(cfg, indent=2))

    def start(self):
        sh("systemctl restart opensnitch")
        time.sleep(4)
        # if eBPF failed to load, retry with proc monitor so attribution still works
        if sh("journalctl -u opensnitch --since '-15s' | grep -qi 'ebpf.*\\(fail\\|error\\|cannot\\)'").returncode == 0:
            cfg = json.loads(Path("/etc/opensnitchd/default-config.json").read_text())
            cfg["ProcMonitorMethod"] = "proc"
            Path("/etc/opensnitchd/default-config.json").write_text(json.dumps(cfg, indent=2))
            sh("systemctl restart opensnitch")
            time.sleep(4)

    def pre_trial(self):
        self._snap = {"t": time.time()}

    _re_path = re.compile(r'PATH="([^"]*)"')
    _re_dst = re.compile(r'DST="([^"]*)"')
    _re_dpt = re.compile(r'DPT="([^"]*)"')

    def collect(self, gt: GT) -> Observation:
        # opensnitch logs every intercepted connection to syslog (identifier
        # "opensnitch") in a bracketed format: CONNECTION - [SRC=".." DST=".."
        # DPT=".." PROTO=".." PID=".." PATH=".."]. Match our unique exe in PATH.
        # The log reaches journald via SIEM-logger -> syslog -> journald, which can
        # lag the connection by several seconds. Poll (widening the window to 'now')
        # until our exe appears or a deadline, so a slow flush is not a spurious miss
        # -- this only waits out latency; a genuine non-interception still fails.
        since = f"@{gt.t0 - 2:.0f}"
        attributed, names, count, by_dst = False, [], 0, False
        deadline = time.time() + 12
        while True:
            until = f"@{time.time():.0f}"
            r = sh(["journalctl", "-t", "opensnitch", "-o", "cat", "--since", since, "--until", until])
            attributed, names, count, by_dst = False, [], 0, False
            for line in r.stdout.splitlines():
                if "CONNECTION" not in line:
                    continue
                pm = self._re_path.search(line)
                path = pm.group(1) if pm else ""
                if gt.exe in path:
                    attributed = True
                    names.append(path)
                    count += 1
                else:
                    dm = self._re_dst.search(line)
                    if dm and dm.group(1) == gt.peer:
                        by_dst = True
            if attributed or time.time() >= deadline:
                break
            time.sleep(0.8)
        return Observation(
            flow_detected=attributed or by_dst,
            proc_attributed=attributed,
            names=names[:3],
            sent=None,
            recv=None,
            note=f"{count} connection record(s) matched process" + ("" if attributed else "; flow seen by dst only" if by_dst else ""),
        )

    def pids(self):
        return _systemd_mainpid("opensnitch")

    def stop(self):
        sh("systemctl stop opensnitch")


# --------------------------------------------------------------------------- #
# sniffnet: GUI only, no per-process export; read by OCR of its Program panel
# --------------------------------------------------------------------------- #
class Sniffnet(ToolAdapter):
    name = "sniffnet"
    VERSION_CMD = "dpkg-query -W -f '${Version}' sniffnet"
    VERSION_SOURCE = "pinned (release .deb)"
    layer = "wire"
    does_attribution = True  # per-process only in the live GUI -> extracted by OCR
    settle = 2.0
    DISPLAY = ":99"
    VERSION = "1.5.1"
    DEB = f"https://github.com/GyulyVGC/sniffnet/releases/download/v{VERSION}/Sniffnet_LinuxDEB_amd64.deb"

    def install(self):
        if self.VERSION not in sh("dpkg-query -W -f '${Version}' sniffnet 2>/dev/null").stdout:
            sh("apt-get install -y xvfb libpcap0.8 libasound2t64 libfontconfig1 libgtk-3-0t64 libxkbcommon-x11-0 tesseract-ocr imagemagick")
            deb = _download(self.DEB, DL / f"sniffnet-{self.VERSION}.deb")
            sh(f"apt-get install -y --allow-downgrades {deb}", timeout=600)

    def start(self):
        # sniffnet is a native GPU GUI with no export, so run it under Xvfb and
        # OCR its Overview "Program" panel for per-process attribution.
        sh("pkill -x Xvfb; rm -f /tmp/.X99-lock")
        self.xvfb = subprocess.Popen(["Xvfb", self.DISPLAY, "-screen", "0", "1600x1000x24"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        self._launch()

    def _launch(self):
        env = {**os.environ, "DISPLAY": self.DISPLAY, "ICED_BACKEND": "tiny-skia"}
        self.proc = subprocess.Popen(["sniffnet", "--adapter", "vbench0"], env=env, stdout=open(self.sess / "sniffnet.log", "w"), stderr=subprocess.STDOUT)
        time.sleep(6)

    def pre_trial(self):
        self._snap = {}
        # the Program panel accumulates a row per program for the whole session
        # and shows only a few at a time; a fresh instance lists only this trial
        super().stop()
        sh("pkill -x sniffnet")
        time.sleep(1)
        self._launch()

    _units = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}
    # Program panel: right-hand column of the lower panel row of the app window
    PROG_PANEL = "300x220+890+400"

    def _ocr(self):
        # import (X screenshot) or tesseract can hang if Xvfb wedges; run both
        # without a shell and cap them so a stuck OCR falls back to flow level
        # instead of blocking the whole run indefinitely.
        png = self.sess / "sniffnet.png"
        crop = self.sess / "sniffnet_program.png"
        try:
            sh(["import", "-window", "root", str(png)], timeout=30, env={**os.environ, "DISPLAY": self.DISPLAY})
            # the three panels share text lines in a full-window OCR
            sh(["convert", str(png), "-crop", self.PROG_PANEL, "+repage", "-colorspace", "gray", "-resize", "300%", str(crop)], timeout=30)
            r = sh(["tesseract", str(crop if crop.exists() else png), "-", "--psm", "6"], timeout=30)
            return r.stdout
        except subprocess.TimeoutExpired:
            sh("pkill -x import 2>/dev/null")
            return ""

    def _ocr_rows(self, text):
        """Program-panel rows as (label, bytes). Sniffnet lists traffic it cannot
        attribute under a '?' row: a byte figure with no program name."""
        rows = []
        for line in text.splitlines():
            figs = re.findall(r"([\d.]+)\s*(TB|GB|MB|KB|B)\b", line)
            if not figs:
                continue
            head = re.sub(r"([\d.]+)\s*(TB|GB|MB|KB|B)\b.*$", "", line)
            name = ""
            for tok in head.replace("(", " ").replace(")", " ").split():
                if len(re.sub(r"[^A-Za-z0-9]", "", tok)) >= 3:
                    name = tok.strip("_.,:")
            rows.append((name or "?", float(figs[-1][0]) * self._units[figs[-1][1]]))
        return rows

    def _ocr_process(self, gt, text):
        """(bytes, label) for our process, or (None, "?") when Sniffnet listed the
        traffic without naming a program, or (None, "") when nothing was read."""
        import difflib

        rows = self._ocr_rows(text)
        for label, nbytes in rows:
            if label != "?" and (difflib.SequenceMatcher(None, label.lower(), gt.exe.lower()).ratio() > 0.62 or gt.exe.split(".")[0][3:] in label.lower()):
                return nbytes, label
        return (None, "?") if any(lbl == "?" for lbl, _ in rows) else (None, "")

    def collect(self, gt: GT) -> Observation:
        # per-process via OCR of the live GUI
        ocr_bytes, label = None, ""
        try:
            ocr_bytes, label = self._ocr_process(gt, self._ocr())
        except Exception:
            ocr_bytes, label = None, ""
        # sniffnet shows ONE combined per-program total, not a per-direction
        # split: for a single-direction scenario that total IS that direction; a
        # duplex total cannot be split, so the untestable direction is N/A.
        dirs = gt.test_dirs or ["ingress"]
        single = len(dirs) == 1
        if ocr_bytes is not None:
            note = "per-program total from the GUI" if single else "per-program total from the GUI; one combined figure, cannot split direction"
            return Observation(
                flow_detected=True,
                proc_attributed=True,
                names=[label],
                sent=ocr_bytes if single and dirs[0] == "egress" else None,
                recv=ocr_bytes if single and dirs[0] == "ingress" else None,
                note=note,
            )
        if label == "?":
            # Sniffnet counted the traffic but named no program: its own
            # unattributed row.
            unattr = next((b for lbl, b in self._ocr_rows(self._ocr()) if lbl == "?"), 0)
            return Observation(
                flow_detected=True,
                proc_attributed=False,
                names=["?"],
                sent=unattr if single and dirs[0] == "egress" else None,
                recv=unattr if single and dirs[0] == "ingress" else None,
                note="listed unattributed (?) by Sniffnet",
            )
        return Observation(flow_detected=False, proc_attributed=False, names=[], sent=0, recv=0, note="no Program row")

    def stop(self):
        for p in (getattr(self, "proc", None), getattr(self, "xvfb", None)):
            if p and p.poll() is None:
                p.terminate()
        sh("pkill -x sniffnet; pkill -x Xvfb")
        time.sleep(1)


# --------------------------------------------------------------------------- #
# Little Snitch for Linux: undocumented local WebSocket used by its web UI
# --------------------------------------------------------------------------- #
class LittleSnitch(ToolAdapter):
    name = "littlesnitch"
    VERSION_CMD = "dpkg-query -W -f '${Version}' littlesnitch"
    VERSION_SOURCE = "pinned (release .deb)"
    layer = "socket"
    settle = 3.0
    VERSION = "1.0.9"
    DEB = f"https://obdev.at/downloads/littlesnitch-linux/littlesnitch_{VERSION}_amd64.deb"
    # little-snitch attributes traffic to the top-level "responsible" app, not the
    # leaf process, so each generator must run as its own detached transient
    # systemd service to get a distinct app row. --pipe keeps stdout (the RESULT
    # line) flowing back to the harness.
    gen_prefix = ["systemd-run", "--pipe", "--quiet", "--collect"]

    def install(self):
        self.available = False
        if self.version() == self.VERSION:
            self.available = True
            return
        try:
            deb = _download(self.DEB, DL / "littlesnitch.deb")
            if Path(deb).stat().st_size > 100000:
                r = sh(f"apt-get install -y {deb}", timeout=600)
                self.available = r.returncode == 0 or bool(sh("command -v littlesnitch littlesnitchd").returncode == 0)
        except Exception:
            self.available = False

    def start(self):
        if not getattr(self, "available", False):
            return
        # clear the persistent traffic history so per-app cumulative stats start
        # fresh (little-snitch aggregates by name across restarts otherwise).
        sh("systemctl stop littlesnitch")
        sh("rm -f /var/lib/littlesnitch/connections.sqlite")
        sh("systemctl start littlesnitch")
        # wait for the daemon's web socket to come up
        self.stream = None
        for _ in range(20):
            if sh("ss -ltn 2>/dev/null | grep -q 127.0.0.1:3031").returncode == 0:
                break
            time.sleep(0.5)
        time.sleep(2)
        import lsws

        self.stream = lsws.LittleSnitchStream()
        self.stream.start()
        time.sleep(1)

    def pre_trial(self):
        self._snap = {}

    def collect(self, gt: GT) -> Observation:
        if not getattr(self, "available", False):
            return Observation(na=True, note="not installable in this environment")
        stream = getattr(self, "stream", None)
        if not stream:
            return Observation(na=True, note="WebSocket stream unavailable")
        # each generator ran as its own transient systemd service under a globally
        # unique name (little-snitch aggregates by process name over history), so
        # its distinct app row's cumulative stats equal this trial's bytes. Poll
        # until the app appears and its bytes reach the known amount or stabilize.
        target = 0.95 * (gt.app_sent + gt.app_recv)
        prev = None
        stable = 0
        found = None
        for _ in range(35):
            found = stream.find(gt.exe)
            if found is not None:
                if target > 0 and (found[0] + found[1]) >= target:
                    break
                if found == prev:
                    stable += 1
                    if stable >= 4:
                        break
                else:
                    stable = 0
                prev = found
            time.sleep(0.6)
        if found is None:
            return Observation(flow_detected=False, proc_attributed=False, sent=0, recv=0, note="no matching app row")
        return Observation(flow_detected=True, proc_attributed=True, names=[gt.exe], sent=found[0], recv=found[1], note="WebSocket per-app stats")

    def pids(self):
        return _systemd_mainpid("littlesnitch")

    def stop(self):
        stream = getattr(self, "stream", None)
        if stream:
            stream.stop()
        sh("systemctl stop littlesnitch 2>/dev/null")


# --------------------------------------------------------------------------- #
# bcc-tools eBPF baseline — tcpconnect (detection) + tcplife (TCP bytes)
# --------------------------------------------------------------------------- #
class Bcc(ToolAdapter):
    name = "bcc-baseline"
    # read the built library's soname: probing the tools themselves would attach BPF
    VERSION = "0.37.0"  # must match BCC_VER in lib/build_bcc.sh
    VERSION_CMD = "readlink -f /usr/local/lib/libbcc.so"
    VERSION_SOURCE = "pinned (built from source tag)"
    layer = "socket"
    settle = 2.0

    # built from source by lib/build_bcc.sh (the distro package fails to
    # JIT-compile against the 7.0 kernel headers). make install puts
    # libbcc.so in /usr/local/lib, the tools in /usr/local/share/bcc/tools, and
    # the python bindings on the system path -- no PYTHONPATH override needed.
    UP_TOOLS = "/usr/local/share/bcc/tools"

    def install(self):
        self.env = dict(os.environ)
        self.env["PYTHONUNBUFFERED"] = "1"  # else tcplife's low-volume output stays buffered
        self.env["LD_LIBRARY_PATH"] = "/usr/local/lib"
        if self.version() != self.VERSION or not Path(f"{self.UP_TOOLS}/tcplife").exists():
            r = sh(f"bash {BENCH}/lib/build_bcc.sh", timeout=3600)
            if r.returncode != 0:
                raise RuntimeError(f"bcc build failed: {r.stderr[-800:]}")
            if self.version() != self.VERSION:
                raise RuntimeError(f"bcc {self.VERSION} build failed, found {self.version() or 'nothing'}")
        self.tcplife = f"{self.UP_TOOLS}/tcplife"
        self.tcpconnect = f"{self.UP_TOOLS}/tcpconnect"

    def start(self):
        self.life = self.sess / "tcplife.log"
        self.conn = self.sess / "tcpconnect.log"
        # tcplife -s = CSV: PID,COMM,...,TX_KB,RX_KB per closed TCP session
        self.proc = subprocess.Popen(["python3", "-u", self.tcplife, "-s"], env=self.env, stdout=open(self.life, "w"), stderr=subprocess.STDOUT)
        self.proc2 = subprocess.Popen(["python3", "-u", self.tcpconnect], env=self.env, stdout=open(self.conn, "w"), stderr=subprocess.STDOUT)
        time.sleep(8)
        # bcc JIT-compiles its programs against the running kernel's headers; on
        # very new kernels this can fail. Detect it so we score N/A (not FAIL).
        self.broken = False
        for f in (self.life, self.conn):
            try:
                if "Failed to compile BPF" in open(f, errors="replace").read():
                    self.broken = True
            except FileNotFoundError:
                pass

    def pre_trial(self):
        self._life0 = self._count_lines(self.life)
        self._conn0 = self._count_lines(self.conn)

    def _count_lines(self, p):
        try:
            return sum(1 for _ in open(p, errors="replace"))
        except FileNotFoundError:
            return 0

    def collect(self, gt: GT) -> Observation:
        # the JIT compile can fail after start()'s check, so re-check here too.
        if not getattr(self, "broken", False):
            for f in (self.life, self.conn):
                try:
                    if "Failed to compile BPF" in open(f, errors="replace").read():
                        self.broken = True
                except FileNotFoundError:
                    pass
        if getattr(self, "broken", False):
            return Observation(na=True, note="bcc programs fail to JIT-compile against the 7.0 kernel headers")
        # bcc tcplife/tcpconnect are TCP-only
        if gt.proto not in ("tcp",):
            return Observation(na=True, note="bcc tcplife/tcpconnect are TCP-only")
        # tcpconnect logs on connect (prompt) but tcplife logs on session CLOSE,
        # whose flush can lag the transfer by seconds -- reading once races it.
        # Poll until the bytes row for our exe appears or a deadline, so a slow
        # close-flush is not a spurious miss. Only waits out latency; a genuinely
        # unseen session still records 0.
        attributed = False
        names = []
        sent = recv = 0.0
        seen = False
        deadline = time.time() + 12
        while True:
            attributed, names, sent, recv, seen = False, [], 0.0, 0.0, False
            try:
                for ln in open(self.conn, errors="replace").read().splitlines()[self._conn0 :]:
                    if gt.exe in ln:
                        attributed = True
                        names.append(gt.exe)
            except FileNotFoundError:
                pass
            try:
                for ln in open(self.life, errors="replace").read().splitlines()[self._life0 :]:
                    if gt.exe not in ln:
                        continue
                    parts = ln.split(",")
                    # CSV header: PID,COMM,LADDR,LPORT,RADDR,RPORT,TX_KB,RX_KB,MS
                    if len(parts) >= 8:
                        try:
                            sent += float(parts[-3]) * 1024
                            recv += float(parts[-2]) * 1024
                            seen = True
                        except ValueError:
                            continue
            except FileNotFoundError:
                pass
            if seen or time.time() >= deadline:
                break
            time.sleep(0.8)
        return Observation(
            flow_detected=attributed or seen, proc_attributed=attributed, names=names[:1], sent=int(sent) if seen else 0, recv=int(recv) if seen else 0, note="tcplife fires on session close"
        )

    def stop(self):
        for p in (getattr(self, "proc", None), getattr(self, "proc2", None)):
            if p and p.poll() is None:
                p.terminate()
        sh("pkill -f tcplife; pkill -f tcpconnect")


# --------------------------------------------------------------------------- #
# bcc tcptop — per-process TCP throughput (eBPF), the bandwidth sibling of the
# tcplife/tcpconnect baseline. Same upstream build. TCP-only.
# --------------------------------------------------------------------------- #
class BccTcptop(ToolAdapter):
    name = "bcc-tcptop"
    VERSION = "0.37.0"  # must match BCC_VER in lib/build_bcc.sh
    VERSION_CMD = "readlink -f /usr/local/lib/libbcc.so"
    VERSION_SOURCE = "pinned (built from source tag)"
    layer = "socket"  # hooks tcp_sendmsg / tcp_cleanup_rbuf -> app bytes
    settle = 2.0

    def install(self):
        self.env = dict(os.environ)
        self.env["PYTHONUNBUFFERED"] = "1"
        self.env["LD_LIBRARY_PATH"] = "/usr/local/lib"
        up = f"{Bcc.UP_TOOLS}/tcptop"
        if self.version() != self.VERSION or not Path(up).exists():
            r = sh(f"bash {BENCH}/lib/build_bcc.sh", timeout=3600)
            if r.returncode != 0:
                raise RuntimeError(f"bcc build failed: {r.stderr[-800:]}")
            if self.version() != self.VERSION:
                raise RuntimeError(f"bcc {self.VERSION} build failed, found {self.version() or 'nothing'}")
        self.tcptop = up

    def start(self):
        self.log = self.sess / "tcptop.log"
        # -C: don't clear the screen; 1s interval. rows are per-interval throughput
        # "PID COMM(<=12) LADDR RADDR RX_KB TX_KB" -> sum the intervals per exe.
        self.proc = subprocess.Popen(["python3", "-u", self.tcptop, "-C", "1"], env=self.env, stdout=open(self.log, "w"), stderr=subprocess.STDOUT)
        time.sleep(8)
        self.broken = self._broken()

    def _broken(self):
        try:
            return "Failed to compile BPF" in open(self.log, errors="replace").read()
        except FileNotFoundError:
            return False

    def pre_trial(self):
        self._n0 = sum(1 for _ in open(self.log, errors="replace")) if self.log.exists() else 0

    def collect(self, gt: GT) -> Observation:
        if self.broken or self._broken():
            return Observation(na=True, note="bcc tcptop fails to JIT-compile against the 7.0 kernel headers")
        if gt.proto != "tcp":
            return Observation(na=True, note="bcc tcptop is TCP-only")
        sent = recv = 0.0
        attributed = False
        names = []
        rows = open(self.log, errors="replace").read().splitlines()[self._n0 :]
        for ln in rows:
            parts = ln.split()
            # data rows only: numeric PID + >=6 cols (skip headers / loadavg lines)
            if len(parts) < 6 or not parts[0].isdigit():
                continue
            # this bcc build renders comm as a python bytes repr truncated to 12
            # chars, e.g. "b'bg_tcp_dl." -> strip the b'...' wrapper. the result is
            # a prefix of gt.exe (the trailing trial number may be truncated off).
            comm = parts[1]
            if comm[:2] in ("b'", 'b"'):
                comm = comm[2:]
            comm = comm.rstrip("'\"")
            if not (comm and (gt.exe.startswith(comm) or comm in gt.exe)):
                continue
            try:
                recv += float(parts[-2]) * 1024  # RX_KB
                sent += float(parts[-1]) * 1024  # TX_KB
            except ValueError:
                continue
            attributed = True
            names.append(comm)
        return Observation(
            flow_detected=attributed,
            proc_attributed=attributed,
            names=names[:1],
            sent=int(sent) if attributed else 0,
            recv=int(recv) if attributed else 0,
            note="tcptop per-interval KB summed over the trial",
        )

    def stop(self):
        p = getattr(self, "proc", None)
        if p is not None and p.poll() is None:
            p.terminate()
        # match the monitor's path, NOT a bare "tcptop" (which also matches the
        # harness's own "--tools bcc-tcptop,..." cmdline and would kill the run).
        sh("pkill -f 'bcc/tools/tcptop'")


# --------------------------------------------------------------------------- #
# bpftrace: a hand-rolled per-process TCP bandwidth monitor.
# Same hooks as tcptop. TCP-only.
# --------------------------------------------------------------------------- #
class Bpftrace(ToolAdapter):
    name = "bpftrace"
    VERSION_CMD = "bpftrace --version"
    VERSION_SOURCE = "distro package (recorded, not pinned)"
    layer = "socket"
    settle = 2.0
    # arg2 of tcp_sendmsg is size (bytes queued to send); arg1 of tcp_cleanup_rbuf
    # is copied (bytes handed to userspace). key by comm; print+clear each second.
    SCRIPT = "kprobe:tcp_sendmsg { @s[comm] = sum(arg2); } kprobe:tcp_cleanup_rbuf /arg1 > 0/ { @r[comm] = sum(arg1); } interval:s:1 { print(@s); print(@r); clear(@s); clear(@r); }"
    _rowre = re.compile(r"@([sr])\[(.+?)\]: (\d+)")

    def install(self):
        if sh("command -v bpftrace").returncode != 0:
            sh("apt-get install -y bpftrace", timeout=600)

    def start(self):
        self.log = self.sess / "bpftrace.log"
        self.proc = subprocess.Popen(["bpftrace", "-e", self.SCRIPT], stdout=open(self.log, "w"), stderr=subprocess.STDOUT)
        time.sleep(8)

    def pre_trial(self):
        self._n0 = sum(1 for _ in open(self.log, errors="replace")) if self.log.exists() else 0

    def collect(self, gt: GT) -> Observation:
        if gt.proto != "tcp":
            return Observation(na=True, note="this bpftrace probe hooks tcp_* only (TCP)")
        sent = recv = 0.0
        attributed = False
        names = []
        rows = open(self.log, errors="replace").read().splitlines()[self._n0 :]
        for ln in rows:
            m = self._rowre.search(ln)
            if not m:
                continue
            kind, comm, val = m.group(1), m.group(2), int(m.group(3))
            if not (comm in gt.exe or gt.exe in comm):
                continue
            if kind == "s":
                sent += val
            else:
                recv += val
            attributed = True
            if comm not in names:
                names.append(comm)
        return Observation(
            flow_detected=attributed,
            proc_attributed=attributed,
            names=names[:1],
            sent=int(sent) if attributed else 0,
            recv=int(recv) if attributed else 0,
            note="bpftrace tcp_sendmsg/tcp_cleanup_rbuf, summed per second",
        )

    def stop(self):
        p = getattr(self, "proc", None)
        if p is not None and p.poll() is None:
            p.terminate()
        # 'bpftrace -e' matches the monitor but not the harness's "--tools ...,bpftrace"
        sh("pkill -f 'bpftrace -e'")


# --------------------------------------------------------------------------- #
# Sysdig — syscall-capture per-process network bytes (a different mechanism than
# the socket-hook tools: it sums bytes moved by network I/O syscalls).
# --------------------------------------------------------------------------- #
class Sysdig(ToolAdapter):
    name = "sysdig"
    VERSION_CMD = "sysdig --version"
    VERSION_SOURCE = "distro package (recorded, not pinned)"
    layer = "socket"  # evt.rawres = bytes moved by the syscall (app layer)
    settle = 2.5
    # kernel-side filter to only our generators keeps the captured event volume
    # (and thus overhead) low. io_dir is read/write; rawres is bytes moved.
    # Two branches, because fd.type classifies INET sockets only: packet sockets
    # (AF_PACKET) report no fd.type, so they are matched by the socket-I/O syscall
    # names instead. File I/O (read/write/pread/pwrite) matches neither branch.
    SOCK_SYSCALLS = "send,sendto,sendmsg,sendmmsg,recv,recvfrom,recvmsg,recvmmsg"
    FILTER = f"(fd.type in (ipv4,ipv6) or evt.type in ({SOCK_SYSCALLS})) and evt.is_io=true and evt.rawres>0 and proc.name contains bg"
    FMT = "%proc.name %evt.io_dir %evt.rawres"

    def install(self):
        if sh("command -v sysdig").returncode != 0:
            sh("apt-get install -y sysdig", timeout=600)

    def start(self):
        self.log = self.sess / "sysdig.log"
        # modern sysdig defaults to the CO-RE eBPF probe, no kmod build.
        self.proc = subprocess.Popen(["sysdig", "-p", self.FMT, self.FILTER], stdout=open(self.log, "w"), stderr=subprocess.STDOUT)
        time.sleep(8)
        self.broken = self._broken()

    def _broken(self):
        try:
            txt = open(self.log, errors="replace").read().lower()
            return "error" in txt and ("probe" in txt or "scap" in txt or "driver" in txt)
        except FileNotFoundError:
            return False

    def pre_trial(self):
        self._n0 = sum(1 for _ in open(self.log, errors="replace")) if self.log.exists() else 0

    def collect(self, gt: GT) -> Observation:
        if self.broken or self._broken():
            return Observation(na=True, note="Sysdig probe failed to load on this kernel")
        sent = recv = 0.0
        attributed = False
        names = []
        rows = open(self.log, errors="replace").read().splitlines()[self._n0 :]
        for ln in rows:
            parts = ln.split()
            if len(parts) < 3:
                continue
            comm, io_dir, raw = parts[0], parts[-2], parts[-1]
            if not (comm in gt.exe or gt.exe in comm or gt.exe.startswith(comm)):
                continue
            try:
                nbytes = int(raw)
            except ValueError:
                continue
            if io_dir[:1] == "w":  # 'write' or 'w'
                sent += nbytes
            elif io_dir[:1] == "r":  # 'read' or 'r'
                recv += nbytes
            else:
                continue
            attributed = True
            if comm not in names:
                names.append(comm)
        return Observation(
            flow_detected=attributed,
            proc_attributed=attributed,
            names=names[:1],
            sent=int(sent) if attributed else 0,
            recv=int(recv) if attributed else 0,
            note="Sysdig network I/O syscall bytes, per process",
        )

    def stop(self):
        p = getattr(self, "proc", None)
        if p is not None and p.poll() is None:
            p.terminate()
        sh("pkill -f 'sysdig -p'")


ADAPTERS = {c.name: c for c in [Picosnitch, Nethogs, Bandwhich, OpenSnitch, Sniffnet, LittleSnitch, Bcc, BccTcptop, Bpftrace, Sysdig]}
