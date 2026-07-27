"""Resource profiler for the benchmark: sample a tool's whole process tree
(CPU + PSS memory) at a fixed cadence and report avg/peak.

Uniform across every tool because it profiles by PID subtree, not by any
tool-specific mechanism: each adapter reports its root PID(s) (its subprocess
handle, or its systemd service's MainPID for a daemon) via pids(), and this
walks the /proc tree under those roots each sample. Overhead is a handful of
small /proc reads per second, so profiling does not perturb the tool.

CPU is utime+stime deltas of the live tree. Memory is PSS (proportional set
size) summed across the tree: each shared page is charged once, split across
its sharers, so a multi-process tool's shared libc/interpreter/BPF pages are
not double-counted. Short-lived grandchildren that spawn and exit entirely
between 1 Hz samples are not captured.
"""

import os
import threading
import time

CLK_TCK = os.sysconf("SC_CLK_TCK")


def _ppids():
    """{pid: ppid} for all live processes."""
    out = {}
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        pid = int(name)
        try:
            with open(f"/proc/{pid}/stat") as f:
                # comm (field 2) may contain spaces/parens -> split after the last ')'
                after = f.read().rsplit(")", 1)[1].split()
            out[pid] = int(after[1])  # ppid
        except (OSError, ValueError, IndexError):
            continue
    return out


def _tree(roots):
    """Every pid in the subtrees rooted at `roots` (inclusive)."""
    ppids = _ppids()
    children = {}
    for pid, pp in ppids.items():
        children.setdefault(pp, []).append(pid)
    seen, stack = set(), [r for r in roots if r]
    while stack:
        pid = stack.pop()
        if pid in seen:
            continue
        seen.add(pid)
        stack.extend(children.get(pid, []))
    return seen


def _cpu_ticks(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            after = f.read().rsplit(")", 1)[1].split()
        return int(after[11]) + int(after[12])  # utime + stime
    except (OSError, ValueError, IndexError):
        return 0


def _pss_bytes(pid):
    # Pss: private pages + each shared page divided by its number of sharers.
    # smaps_rollup is a single pre-aggregated file (one read per process).
    try:
        with open(f"/proc/{pid}/smaps_rollup") as f:
            for line in f:
                if line.startswith("Pss:"):
                    return int(line.split()[1]) * 1024  # kB -> bytes
    except (OSError, ValueError, IndexError):
        pass
    return 0


class ResProfiler(threading.Thread):
    def __init__(self, roots_fn, interval=1.0):
        super().__init__(daemon=True)
        self.roots_fn = roots_fn  # callable -> list[int], re-evaluated each sample
        self.interval = interval
        self._stop = threading.Event()
        self.samples = []  # list of (cpu_pct, pss_bytes)
        self._last_ticks = None
        self._last_t = None

    def run(self):
        while not self._stop.is_set():
            t = time.monotonic()
            try:
                roots = self.roots_fn() or []
            except Exception:
                roots = []
            tree = _tree(roots) if roots else set()
            ticks = sum(_cpu_ticks(p) for p in tree)
            pss = sum(_pss_bytes(p) for p in tree)
            if self._last_ticks is not None and self._last_t is not None:
                dt = t - self._last_t
                if dt > 0:
                    dticks = max(0, ticks - self._last_ticks)
                    cpu_pct = 100.0 * (dticks / CLK_TCK) / dt
                    self.samples.append((cpu_pct, pss))
            self._last_ticks, self._last_t = ticks, t
            self._stop.wait(self.interval)

    def stop(self):
        self._stop.set()
        try:
            self.join(timeout=self.interval * 2 + 2)
        except RuntimeError:
            pass

    def summary(self):
        if not self.samples:
            return None
        cpus = [c for c, _ in self.samples]
        psss = [p / 1048576 for _, p in self.samples]
        return {
            "cpu_avg_pct": round(sum(cpus) / len(cpus), 1),
            "cpu_p50_pct": round(_pct(cpus, 50), 1),
            "cpu_p90_pct": round(_pct(cpus, 90), 1),
            "cpu_p95_pct": round(_pct(cpus, 95), 1),
            "cpu_p99_pct": round(_pct(cpus, 99), 1),
            "cpu_peak_pct": round(max(cpus), 1),  # single-sample max: kept for reference, not published
            "pss_avg_mb": round(sum(psss) / len(psss), 1),
            "pss_p95_mb": round(_pct(psss, 95), 1),
            "pss_peak_mb": round(max(psss), 1),
            "samples": len(self.samples),
        }


def _pct(xs, q):
    """Linear-interpolated q-th percentile of xs (q in 0..100). Stdlib only."""
    if not xs:
        return 0.0
    s = sorted(xs)
    if len(s) == 1:
        return s[0]
    idx = q / 100.0 * (len(s) - 1)
    lo = int(idx)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] * (1 - (idx - lo)) + s[hi] * (idx - lo)
