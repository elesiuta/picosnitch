#!/usr/bin/env python3
"""Benchmark orchestrator.

Runs as root. For each tool (in isolation): install -> start -> smoke control ->
every scenario x N trials -> score -> stop. Persists raw JSON and generates the
markdown scorecards.

    sudo python3 lib/run.py --tools all --trials 5
    sudo python3 lib/run.py --tools picosnitch,nethogs --scenarios s01,s05
    sudo python3 lib/run.py --report-only
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import report as reportmod
from adapters import ADAPTERS
from harness import ERROR, FAIL, NA, RESULTS, Ctx, Netlab, combine_trials, gt_directions, save_json, score_bandwidth, score_detection
from resprof import ResProfiler
from scenarios import build_scenarios

DEFAULT_TOOLS = ["picosnitch", "nethogs", "bandwhich", "opensnitch", "littlesnitch", "bcc-baseline", "bcc-tcptop", "bpftrace", "sysdig", "sniffnet"]

# Fairness isolation: only the tool under test may run during its own benchmark.
# Three tools run as systemd services and two of them (opensnitch,
# little-snitch) auto-start at boot, so without this they would be capturing
# concurrently during another tool's trials and taint the comparison. Before each
# tool we stop every OTHER service-based monitor and verify none is left alive.
# Each service-based adapter (re)starts its own daemon for its own turn; the
# process-based tools (nethogs, bandwhich, sniffnet, bcc, bpftrace, sysdig) are
# launched and killed by their own adapters within run_tool, so they never leak
# across tools.
MONITOR_SERVICES = ("picosnitch", "opensnitch", "littlesnitch")
# pgrep -f cmdline signatures to confirm each daemon is actually gone. None may
# start with '-' or pgrep parses it as an option.
_MONITOR_SIG = {
    "picosnitch": "picosnitch start-no-daemon",  # service-worker cmdline
    "opensnitch": "opensnitchd",
    "littlesnitch": "littlesnitch --daemon",
}


def quiesce_other_monitors(current):
    """Stop every service-based monitor except the one under test, then poll until no
    competing monitor process remains. `systemctl stop` can return before the daemon
    has fully exited its cgroup, so a fixed sleep would be racy -- poll instead so the
    tool under test truly runs alone. Logs the isolation result as an auditable record."""
    for svc in MONITOR_SERVICES:
        if svc != current:
            subprocess.run(["systemctl", "stop", svc], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # `systemctl stop` blocks until the daemon's MainPID exits, but opensnitch and
    # little-snitch keep tearing down eBPF/child processes for ~10s after that. Wait
    # out that graceful teardown (rather than SIGKILL, which could orphan opensnitch's
    # nftables/eBPF rules and taint the next tool) so each tool truly starts alone.
    others = [(t, sig) for t, sig in _MONITOR_SIG.items() if t != current]
    stray = [t for t, _ in others]
    for _ in range(60):  # up to ~30s for the daemons to finish exiting
        stray = [t for t, sig in others if subprocess.run(["pgrep", "-f", sig], stdout=subprocess.DEVNULL).returncode == 0]
        if not stray:
            break
        time.sleep(0.5)
    if stray:
        print(f"[{current}] WARNING: competing monitor(s) still running: {stray}", flush=True)
    else:
        print(f"[{current}] isolation OK: no other monitor daemon running", flush=True)


def run_trial(ad, scn, ctx):
    """One trial: snapshot -> run traffic -> settle -> collect -> score."""
    ad.pre_trial()
    gt = scn.run(ctx)
    gt.test_dirs = scn.directions  # score only the directions this scenario tests
    gtd = {
        "app_sent": gt.app_sent,
        "app_recv": gt.app_recv,
        "wire_egress": gt.wire_egress,
        "wire_ingress": gt.wire_ingress,
        "wire_egress_pkts": gt.wire_egress_pkts,
        "wire_ingress_pkts": gt.wire_ingress_pkts,
        "proto": gt.proto,
        "exe": gt.exe,
        "dirs": gt_directions(gt),
        "ok": gt.ok,
        "raw": gt.raw,
    }
    if not gt.ok:
        # generator/harness failure: never score the tool against broken ground
        # truth -- a harness problem must surface as ERROR, not as a tool FAIL.
        return {
            "gt": gtd,
            "obs": {"detected": False, "attributed": None, "names": [], "sent": None, "recv": None, "note": "generator failed"},
            "det": ERROR,
            "det_note": "generator failed; see gt.raw",
            "bw": ERROR,
            "bw_detail": {"note": "generator failed"},
        }
    time.sleep(ad.settle)
    obs = ad.collect(gt)
    det, detnote = score_detection(obs, gt)
    if ad.does_bandwidth:
        bw, bwdetail = score_bandwidth(obs, gt, ad.layer)
    else:
        bw, bwdetail = NA, {"note": "no bandwidth capability"}
    return {
        "gt": gtd,
        "obs": {"detected": obs.flow_detected, "attributed": obs.proc_attributed, "names": obs.names, "sent": obs.sent, "recv": obs.recv, "note": obs.note},
        "det": det,
        "det_note": detnote,
        "bw": bw,
        "bw_detail": bwdetail,
    }


def run_tool(toolname, scenarios, netlab, trials, profile=True):
    Adapter = ADAPTERS[toolname]
    sess = RESULTS / toolname
    ad = Adapter(sess)
    out = {"tool": toolname, "layer": ad.layer, "does_bandwidth": ad.does_bandwidth, "does_attribution": ad.does_attribution, "scenarios": {}, "control": None, "errors": []}
    print(f"\n########## {toolname} ##########", flush=True)
    quiesce_other_monitors(toolname)  # this tool must be the only monitor running
    try:
        print(f"[{toolname}] install ...", flush=True)
        ad.install()
        # fresh peer server per tool so protocol state (e.g. SCTP associations)
        # can't accumulate across tools and wedge later transfers.
        netlab.start_servers()
        print(f"[{toolname}] start ...", flush=True)
        ad.start()
    except Exception as e:
        out["errors"].append(f"setup: {e}\n{traceback.format_exc()}")
        print(f"[{toolname}] SETUP FAILED: {e}", flush=True)
        try:
            ad.stop()
        except Exception:
            pass
        save_json(sess / "results.json", out)
        return out

    ctx = Ctx(netlab)
    ctx.gen_prefix = list(getattr(ad, "gen_prefix", []))  # e.g. systemd-run for little-snitch
    # resource profiler: sample the tool's process tree (CPU + PSS) across its
    # whole session -- avg is typical cost under the benchmark workload, p95 CPU
    # / peak PSS the worst. runs in a thread; a few /proc reads per second.
    prof = None
    if profile:
        try:
            prof = ResProfiler(ad.pids)
            prof.start()
        except Exception as e:
            out["errors"].append(f"profiler: {e}")
            prof = None
    # smoke controls: bulk TCP download then upload -- both must be seen. A
    # failed control means the tool's setup is broken -- record a setup error
    # and skip its scenarios rather than silently scoring the whole matrix
    # against a broken setup. The upload control also fails when a bandwidth-
    # capable tool reports ZERO egress bytes: an egress-blind capture path
    # would sail through a download-only control and corrupt every egress
    # scenario (accuracy is NOT gated -- a coarse but nonzero measurement
    # passes; the scenarios score it).
    control_ok = False
    try:
        ctl_dl, ctl_ul = build_scenarios()[:2]  # s01 download, s02 upload
        cd = run_trial(ad, ctl_dl, ctx)
        out["control"] = {"det": cd["det"], "bw": cd["bw"], "gt": cd["gt"], "obs": cd["obs"]}
        print(f"[{toolname}] control s01 -> det={cd['det']} bw={cd['bw']} (gt recv={cd['gt']['app_recv']} reported={cd['obs']['recv']})", flush=True)
        cu = run_trial(ad, ctl_ul, ctx)
        out["control_up"] = {"det": cu["det"], "bw": cu["bw"], "gt": cu["gt"], "obs": cu["obs"]}
        print(f"[{toolname}] control s02 -> det={cu['det']} bw={cu['bw']} (gt sent={cu['gt']['app_sent']} reported={cu['obs']['sent']})", flush=True)
        zero_egress = ad.does_bandwidth and (cu["obs"]["sent"] or 0) <= 0
        control_ok = cd["det"] not in (FAIL, ERROR) and cu["det"] not in (FAIL, ERROR) and not zero_egress
    except Exception as e:
        out["errors"].append(f"control: {e}")
        print(f"[{toolname}] control error: {e}", flush=True)
    if not control_ok:
        out["errors"].append("control transfer failed: setup treated as broken, scenarios skipped")
        print(f"[{toolname}] CONTROL FAILED -- skipping scenarios", flush=True)

    for scn in scenarios if control_ok else []:
        rec = {"sid": scn.sid, "name": scn.name, "category": scn.category, "note": scn.note, "desc": scn.desc, "trials": []}
        for t in range(trials):
            try:
                rec["trials"].append(run_trial(ad, scn, ctx))
            except Exception as e:
                rec["trials"].append({"error": str(e)})
                out["errors"].append(f"{scn.sid} trial {t}: {e}")
        det_v = [x.get("det", ERROR) for x in rec["trials"]]
        bw_v = [x.get("bw", ERROR) for x in rec["trials"]]
        rec["det_final"], rec["det_flaky"] = combine_trials(det_v)
        rec["bw_final"], rec["bw_flaky"] = combine_trials(bw_v)
        out["scenarios"][scn.sid] = rec
        print(f"[{toolname}] {scn.sid} {scn.name[:34]:34} det={rec['det_final']:7} bw={rec['bw_final']:7}{' FLAKY' if rec['det_flaky'] or rec['bw_flaky'] else ''}", flush=True)

    if prof:
        prof.stop()
        out["resources"] = prof.summary()
    try:
        ad.stop()
    except Exception as e:
        out["errors"].append(f"stop: {e}")
    save_json(sess / "results.json", out)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tools", default="all")
    ap.add_argument("--scenarios", default="all")
    ap.add_argument("--trials", type=int, default=5)
    ap.add_argument("--report-only", action="store_true")
    ap.add_argument("--no-profile", action="store_true", help="skip CPU/memory resource profiling")
    args = ap.parse_args()

    if args.report_only:
        reportmod.write_reports()
        reportmod.write_findings()
        return

    tools = DEFAULT_TOOLS if args.tools == "all" else args.tools.split(",")
    all_scn = build_scenarios()
    if args.scenarios != "all":
        want = set(args.scenarios.split(","))
        all_scn = [s for s in all_scn if s.sid in want]

    netlab = Netlab()
    print("=== netlab up ===", flush=True)
    netlab.up()
    try:
        for tool in tools:
            run_tool(tool, all_scn, netlab, args.trials, profile=not args.no_profile)
    finally:
        netlab.down()
        print("=== netlab down ===", flush=True)

    reportmod.write_reports()
    reportmod.write_findings()
    print("\n=== reports written to bench/reports/ ===", flush=True)


if __name__ == "__main__":
    main()
