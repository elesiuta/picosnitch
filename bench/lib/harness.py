"""Core benchmark infrastructure: network lab control, dual-layer reference
capture, the scenario framework, the per-trial data model, and scoring.

Everything here is tool-agnostic. Tool adapters live in adapters.py; scenario
definitions in scenarios.py; the CLI orchestration in run.py.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

BENCH = Path(__file__).resolve().parent.parent  # .../bench
BIN = BENCH / "bin"
LIB = BENCH / "lib"
RUNDIR = Path("/opt/bench/run")  # unique per-scenario exe copies
RESULTS = BENCH / "results"
REPORTS = BENCH / "reports"

PEER4 = "10.99.0.2"
PEER6 = "fd00:be0c::2"
HOST4 = "10.99.0.1"
VETH = "vbench0"
NS = "benchpeer"

PORT_TCP, PORT_UDP, PORT_SCTP = 9101, 9102, 9103


def sh(cmd, **kw):
    """Run a shell command, returning CompletedProcess (text mode). A default
    timeout guards against a wedged subprocess (e.g. an OCR screenshot on a
    hung X server) blocking the whole run; the raised TimeoutExpired is caught
    per-trial / per-tool and recorded as an error. Callers that legitimately
    need longer (apt, git clone, source builds) pass an explicit timeout."""
    kw.setdefault("timeout", 300)
    return subprocess.run(cmd, shell=isinstance(cmd, str), text=True, capture_output=True, **kw)


# --------------------------------------------------------------------------- #
# ground truth
# --------------------------------------------------------------------------- #
@dataclass
class GT:
    """Independent ground truth for one trial."""

    app_sent: int = 0  # exact application bytes egress
    app_recv: int = 0  # exact application bytes ingress
    wire_egress: int = 0  # nft L3 bytes host->peer
    wire_egress_pkts: int = 0
    wire_ingress: int = 0  # nft L3 bytes peer->host
    wire_ingress_pkts: int = 0
    t0: float = 0.0
    t1: float = 0.0
    proto: str = ""  # tcp/udp/sctp/icmp/raw253/afpacket
    family: int = 2  # AF_INET=2, AF_INET6=10
    rport: int = 0
    lport: int = 0
    exe: str = ""  # unique executable basename the monitors should see
    peer: str = ""
    ok: bool = True  # did the generator complete cleanly
    raw: str = ""  # generator RESULT line
    syscall_result_unit: str = "bytes"  # unit returned by the generator's data syscall
    test_dirs: list | None = None  # directions the scenario actually tests (set by
    # runner); scoring uses these, not reverse-path ACKs

    def app_ref(self, direction):
        return self.app_sent if direction == "egress" else self.app_recv

    def wire_ref(self, direction):
        return self.wire_egress if direction == "egress" else self.wire_ingress


@dataclass
class Observation:
    """What a monitor reported for one trial. None means 'tool cannot provide'."""

    flow_detected: bool = False  # did any matching traffic/connection show up
    proc_attributed: object = None  # True / False / None(no process concept)
    names: list = field(default_factory=list)  # process names the tool attributed
    sent: object = None  # bytes egress (None = no bandwidth capability)
    recv: object = None  # bytes ingress
    note: str = ""
    na: bool = False  # tool genuinely N/A here (uninstallable, or capability absent) -> score N/A, not FAIL
    invalid: bool = False  # the harness could not extract a measurement (not a tool result)


# --------------------------------------------------------------------------- #
# network lab
# --------------------------------------------------------------------------- #
class Netlab:
    def __init__(self):
        self.script = str(LIB / "netlab.sh")
        self.peer_srv = None
        self.loop_srv = None

    def _run(self, *args):
        return sh(["bash", self.script, *args])

    def up(self):
        self._run("down")
        r = self._run("up")
        if r.returncode != 0:
            raise RuntimeError(f"netlab up failed: {r.stderr}\n{r.stdout}")

    def down(self):
        self.stop_servers()
        self._run("down")

    def reset(self):
        r = self._run("reset")
        if r.returncode != 0:
            raise RuntimeError(f"netlab reset failed (wire reference would be wrong): {r.stderr}")

    def read(self):
        """Return (egress_bytes, egress_pkts, ingress_bytes, ingress_pkts).
        Raises on failure: a broken counter pipeline must abort the trial loudly,
        not silently report zero wire traffic (which would score wire-layer tools
        as N/A 'no reference traffic')."""
        r = self._run("read")
        try:
            a, b, c, d = r.stdout.split()
            return int(a), int(b), int(c), int(d)
        except Exception as e:
            raise RuntimeError(f"netlab read failed (wire ground truth unavailable): stdout={r.stdout!r} stderr={r.stderr!r}") from e

    def peer_mac(self):
        r = sh(["ip", "netns", "exec", NS, "cat", "/sys/class/net/vbench1/address"])
        return r.stdout.strip()

    def start_servers(self):
        """Peer server (in netns) + a loopback server (host netns) for S16."""
        self.stop_servers()
        self.peer_srv = subprocess.Popen(["ip", "netns", "exec", NS, str(BIN / "benchserver")], stdout=open("/tmp/benchsrv_peer.log", "w"), stderr=subprocess.STDOUT)
        # loopback server for S16: a second benchserver in the host netns. Same
        # fixed ports as the peer instance -- no clash, different namespaces.
        # NOTE: binds 0.0.0.0:{9101,9102,9103,443,53} on the host for the whole
        # run (dedicated-machine assumption).
        self.loop_srv = subprocess.Popen([str(BIN / "benchserver")], stdout=open("/tmp/benchsrv_loop.log", "w"), stderr=subprocess.STDOUT)
        time.sleep(1.0)

    def stop_servers(self):
        for p in (self.peer_srv, self.loop_srv):
            if p and p.poll() is None:
                p.terminate()
        sh("pkill -f bin/benchserver")
        self.peer_srv = self.loop_srv = None


# --------------------------------------------------------------------------- #
# scenario framework
# --------------------------------------------------------------------------- #
class Ctx:
    """Passed to each scenario's run(); holds the lab and helpers."""

    def __init__(self, netlab: Netlab):
        self.netlab = netlab
        self._seq = 0
        self._unit = 0
        # When set, every generator launch is wrapped (used by little-snitch to
        # run each generator as its own detached transient systemd service, so
        # it's a distinct top-level app rather than a child of the runner).
        self.gen_prefix = []
        RUNDIR.mkdir(parents=True, exist_ok=True)

    def gen_cmd(self, argv):
        """Apply gen_prefix, giving each launch a unique transient unit name."""
        if not self.gen_prefix:
            return argv
        self._unit += 1
        return [*self.gen_prefix, f"--unit=lsbench{self._unit}.service", "--", *argv]

    def unique(self, base: str) -> str:
        """A UNIQUE PER-TRIAL executable basename (base.N). Uniqueness means every
        trial's process is brand-new, so each monitor's cumulative counter for that
        name equals the trial's own total (no cross-trial delta conflation) and
        attribution is unambiguous. Kept <=15 chars for TASK_COMM_LEN truncation."""
        self._seq += 1
        return f"{base}.{self._seq}"

    def named_gen(self, gen: str, base: str) -> str:
        """Copy a generator binary to a unique per-trial name; return the path."""
        dst = RUNDIR / self.unique(base)
        shutil.copy2(BIN / gen, dst)
        os.chmod(dst, 0o755)
        return str(dst)

    def run_gen(self, argv, timeout=45):
        """Execute a generator, parse its RESULT line into a dict."""
        r = sh(self.gen_cmd(argv), timeout=timeout)
        out = (r.stdout or "") + (r.stderr or "")
        res = {}
        for line in out.splitlines():
            if line.startswith("RESULT "):
                for kv in line.split()[1:]:
                    if "=" in kv:
                        k, v = kv.split("=", 1)
                        res[k] = v
        res["_rc"] = r.returncode
        res["_out"] = out.strip()
        return res


@dataclass
class Scenario:
    sid: str
    name: str
    category: str
    directions: list  # subset of ["egress","ingress"] carrying real traffic
    proto: str  # selector label
    run: object  # callable(Ctx) -> GT
    exe: str  # unique executable basename monitors should attribute
    rport: int = 0
    family: int = 2
    peer: str = PEER4
    desc: str = ""
    note: str = ""  # standing caveat shown in reports


# --------------------------------------------------------------------------- #
# scoring
# --------------------------------------------------------------------------- #
PASS, PARTIAL, FAIL, NA, ERROR = "PASS", "PARTIAL", "FAIL", "N/A", "ERROR"
BW_PASS, BW_PARTIAL = 0.10, 0.25  # ±10% pass, ±25% partial
MAC_HDR = 14  # Ethernet header (dst6+src6+type2)
IP4_HDR = 20
IP6_HDR = 40


def _bw_verdict(ratio):
    d = abs(ratio - 1.0)
    if d <= BW_PASS:
        return PASS
    if d <= BW_PARTIAL:
        return PARTIAL
    return FAIL


def score_detection(obs: Observation, gt: GT):
    """Return (verdict, note)."""
    if obs is None:
        return ERROR, "collection error"
    if obs.invalid:
        return ERROR, obs.note or "measurement could not be extracted"
    if obs.na:
        return NA, obs.note or "not applicable"
    if obs.proc_attributed is None:
        # tool has no per-process concept (e.g. sniffnet): flow-level only
        if obs.flow_detected:
            return PARTIAL, "flow detected but no per-process attribution"
        return FAIL, "flow not detected"
    if not obs.flow_detected:
        return FAIL, "not detected"
    if obs.proc_attributed:
        return PASS, ""
    return PARTIAL, "traffic seen but not attributed to the process (unknown bucket)"


def layer_ref(gt: GT, layer: str, d: str) -> int:
    """Reference bytes for one direction, at the layer a tool counts at.

    socket: application bytes the generator moved.
    frame:  whole Ethernet frames, so the L3 nft count plus one MAC header per
            packet (no FCS on the veth capture path).
    ippayload: the IP payload, so the L3 count minus one IP header per packet.
    """
    if layer == "socket":
        return gt.app_ref(d)
    pkts = gt.wire_egress_pkts if d == "egress" else gt.wire_ingress_pkts
    if layer == "ippayload":
        return gt.wire_ref(d) - (IP6_HDR if gt.family == 10 else IP4_HDR) * pkts
    return gt.wire_ref(d) + MAC_HDR * pkts


def score_bandwidth(obs: Observation, gt: GT, layer: str):
    """Return (verdict, detail-dict). layer in {socket, frame, ippayload}."""
    if obs is None:
        return ERROR, {"note": "collection error"}
    if obs.invalid:
        return ERROR, {"note": obs.note or "measurement could not be extracted"}
    if obs.na or (obs.sent is None and obs.recv is None):
        return NA, {"note": obs.note or "no bandwidth capability"}
    verdicts, detail = [], {}
    for d in gt_directions(gt):
        ref = layer_ref(gt, layer, d)
        raw = obs.sent if d == "egress" else obs.recv
        val = float(raw) if isinstance(raw, (int, float)) else 0.0
        if ref <= 0:
            continue
        ratio = val / ref
        detail[d] = {"reported": val, "ref": ref, "ratio": round(ratio, 4)}
        verdicts.append(_bw_verdict(ratio))
    if not verdicts:
        return NA, {"note": "no reference traffic"}
    order = {FAIL: 0, PARTIAL: 1, PASS: 2}
    worst = min(verdicts, key=lambda v: order[v])
    return worst, detail


def gt_directions(gt: GT):
    # The scenario's DECLARED test directions, so incidental reverse-path ACKs of a
    # bulk transfer aren't scored as a real direction. run_trial always sets
    # test_dirs from scn.directions, so this is the only path that runs.
    td = gt.test_dirs
    if td:
        return list(td)
    # Safety net only (unreachable in normal runs): a byte-threshold guess that can
    # misclassify reverse-path traffic. Kept so a caller that forgot test_dirs fails
    # soft rather than scoring nothing; do not rely on it.
    dirs = []
    if gt.app_sent > (1 << 20) or gt.wire_egress > (1 << 20):
        dirs.append("egress")
    if gt.app_recv > (1 << 20) or gt.wire_ingress > (1 << 20):
        dirs.append("ingress")
    return dirs


def combine_trials(verdicts):
    """Reduce N per-trial verdicts to a cell verdict + a disagreement flag.
    The verdict is the modal one, ties broken toward the worse. The flag is set
    whenever the trials were not unanimous."""
    from collections import Counter

    c = Counter(verdicts)
    flaky = len(set(verdicts)) > 1
    order = {ERROR: -1, FAIL: 0, PARTIAL: 1, NA: 2, PASS: 3}
    # an unresolved trial is not outvoted by the ones that did produce a result
    if ERROR in c:
        return ERROR, flaky
    # N/A dominates only if every trial is N/A
    if all(v == NA for v in verdicts):
        return NA, False
    non_na = [v for v in verdicts if v != NA]
    return sorted(non_na, key=lambda v: (-c[v], order[v]))[0], flaky


def save_json(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, default=str))
