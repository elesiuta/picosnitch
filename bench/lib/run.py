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
from harness import BIN, ERROR, FAIL, NA, RESULTS, Ctx, Netlab, combine_trials, gt_directions, save_json, score_bandwidth, score_detection, sh
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


def preflight(tools, scenarios):
    """Provision what the run assumes exists, before anything runs.

    A stock cloud image has none of this. Without the check a missing prerequisite
    surfaces hours in and reads as a result: no docker turns s17 into ERROR cells
    for every tool, no pipx makes picosnitch's install fail, an unbuilt bin/ fails
    every generator. Only what the SELECTED tools and scenarios need is required, so
    a subset run on a lesser box still works. Loud and up front: missing
    prerequisites are collected and the run aborts before the first tool."""
    sids = {s.sid for s in scenarios}
    missing = []
    sh("apt-get update", timeout=600)  # a fresh image can ship empty package lists

    for b in ("benchgen", "benchgen_static", "benchserver"):
        if not (BIN / b).exists():
            missing.append(f"bin/{b} (compile the helpers first: sudo bash lib/build.sh)")

    if "picosnitch" in tools and sh("command -v pipx").returncode != 0:
        sh("apt-get install -y pipx", timeout=600)
        if sh("command -v pipx").returncode != 0:
            missing.append("pipx (picosnitch is installed with it)")

    if "s17" in sids:  # in-container egress
        if sh("command -v docker").returncode != 0:
            sh("apt-get install -y docker.io", timeout=900)
        subprocess.run(["systemctl", "start", "docker"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if sh("command -v docker").returncode != 0:
            missing.append("docker (s17 runs a generator inside a container)")
        # pull now: a cold pull inside the first trial would time out that trial
        elif sh("docker image inspect alpine:3.20", timeout=60).returncode != 0:
            r = sh("docker pull alpine:3.20", timeout=600)
            if r.returncode != 0:
                missing.append(f"docker image alpine:3.20 ({r.stderr.strip()[:200]})")

    if "s08" in sids and sh("modprobe sctp").returncode != 0:  # SCTP transfer
        missing.append("sctp kernel module (s08); on Ubuntu it ships in linux-modules-extra")

    if missing:
        print("\n!!! PREFLIGHT FAILED -- the run would report these as tool results:", flush=True)
        for m in missing:
            print(f"    missing: {m}", flush=True)
        sys.exit(2)
    print(f"preflight OK ({len(tools)} tools, {len(sids)} scenarios)", flush=True)


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
        raise RuntimeError(f"competing monitor(s) still running: {stray}; this tool would not be measured alone")
    else:
        print(f"[{current}] isolation OK: no other monitor daemon running", flush=True)


def unscored(ad, gtd, note):
    """Trial the harness could not measure (its fault domain, e.g. dead monitor
    or broken ground truth): ERROR, never a tool verdict; N/A stays N/A."""
    return {
        "gt": gtd,
        "obs": {"detected": False, "attributed": None, "names": [], "sent": None, "recv": None, "note": note},
        "det": ERROR,
        "det_note": note,
        "bw": ERROR if ad.does_bandwidth else NA,
        "bw_detail": {"note": note if ad.does_bandwidth else "no bandwidth capability"},
    }


def run_trial(ad, scn, ctx):
    """One trial: snapshot -> run traffic -> settle -> collect -> score."""
    ad.pre_trial()
    if not ad.alive():
        # a dead monitor observes nothing; running traffic would score that as a tool FAIL
        return unscored(ad, {"app_sent": 0, "app_recv": 0, "ok": False}, "monitor process not running at trial start")
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
        return unscored(ad, gtd, "generator failed; see gt.raw")
    time.sleep(ad.settle)
    obs = ad.collect(gt)
    if obs is not None and obs.invalid:
        # the harness could not read a measurement; give the extraction one more
        # chance before recording the trial as unresolved
        time.sleep(ad.settle)
        obs = ad.collect(gt)
    det, detnote = score_detection(obs, gt)
    if ad.does_bandwidth:
        bw, bwdetail = score_bandwidth(obs, gt, ad.bandwidth_layer(gt))
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
    out = {
        "tool": toolname,
        "layer": ad.layer,
        "does_bandwidth": ad.does_bandwidth,
        "does_attribution": ad.does_attribution,
        "run_date": time.strftime("%Y-%m-%d"),
        "version": "",
        "version_source": ad.VERSION_SOURCE,
        "scenarios": {},
        "control": None,
        "errors": [],
    }
    print(f"\n########## {toolname} ##########", flush=True)
    try:
        quiesce_other_monitors(toolname)  # a stuck competing daemon = this tool's setup error; later tools re-check
        print(f"[{toolname}] install ...", flush=True)
        ad.install()
        # read the version from the tool that is actually installed, so reports
        # state observed versions rather than intended ones
        out["version"] = ad.version()
        print(f"[{toolname}] version {out['version'] or 'unknown'} ({ad.VERSION_SOURCE})", flush=True)
        # fresh peer server per tool so protocol state (e.g. SCTP associations)
        # can't accumulate across tools and wedge later transfers.
        netlab.start_servers()
        print(f"[{toolname}] start ...", flush=True)
        ad.start()
    except Exception as e:
        # no scenarios run at all: flagged so the reports say "not measured" instead
        # of rendering the empty matrix as a tool that scored zero
        out["setup_failed"] = True
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
    # Retried once: some monitors miss the first session after their probes
    # attach (BCC's tcplife emits a row only when the session closes). A control
    # that fails both attempts is recorded and published with the tool's results.
    control_ok = False
    try:
        ctl_dl, ctl_ul = build_scenarios()[:2]  # s01 download, s02 upload
        for attempt in (1, 2):
            cd = run_trial(ad, ctl_dl, ctx)
            out["control"] = {"det": cd["det"], "bw": cd["bw"], "gt": cd["gt"], "obs": cd["obs"]}
            print(f"[{toolname}] control s01 (attempt {attempt}) -> det={cd['det']} bw={cd['bw']} (gt recv={cd['gt']['app_recv']} reported={cd['obs']['recv']})", flush=True)
            cu = run_trial(ad, ctl_ul, ctx)
            out["control_up"] = {"det": cu["det"], "bw": cu["bw"], "gt": cu["gt"], "obs": cu["obs"]}
            print(f"[{toolname}] control s02 (attempt {attempt}) -> det={cu['det']} bw={cu['bw']} (gt sent={cu['gt']['app_sent']} reported={cu['obs']['sent']})", flush=True)
            # a bandwidth-capable tool must report bytes in both directions
            zero_bytes = ad.does_bandwidth and ((cu["obs"]["sent"] or 0) <= 0 or (cd["obs"]["recv"] or 0) <= 0)
            control_ok = cd["det"] not in (FAIL, ERROR) and cu["det"] not in (FAIL, ERROR) and not zero_bytes
            if control_ok:
                if attempt > 1:
                    out["errors"].append("control passed on the second attempt (first attempt missed; probe warm-up)")
                break
    except Exception as e:
        out["errors"].append(f"control: {e}")
        print(f"[{toolname}] control error: {e}", flush=True)
    if not control_ok:
        # A control can fail because the tool genuinely does not report the
        # transfer, which is a result rather than a broken setup, so the
        # scenarios still run and the failure is published with them.
        out["errors"].append("control transfer was not reported by this tool on either attempt; its results are published with this caveat")
        print(f"[{toolname}] CONTROL FAILED -- continuing, recorded as a run note", flush=True)

    for scn in scenarios:
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
        print(f"[{toolname}] {scn.sid} {scn.name[:34]:34} det={rec['det_final']:7} bw={rec['bw_final']:7}{' TRIALS-DISAGREED' if rec['det_flaky'] or rec['bw_flaky'] else ''}", flush=True)

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

    preflight(tools, all_scn)

    netlab = Netlab()
    print("=== netlab up ===", flush=True)
    netlab.up()
    outs: dict[str, dict] = {}
    try:
        for tool in tools:
            try:
                outs[tool] = run_tool(tool, all_scn, netlab, args.trials, profile=not args.no_profile)
            except Exception:
                # no single tool's failure may take down the rest of a multi-hour run
                print(f"[{tool}] TOOL ABORTED:\n{traceback.format_exc()}", flush=True)
                # persist the abort: without this the reports would silently pick up
                # a previous run's results.json for this tool and publish them as this run's
                outs[tool] = {"tool": tool, "run_date": time.strftime("%Y-%m-%d"), "setup_failed": True, "scenarios": {}, "control": None, "errors": [f"aborted: {traceback.format_exc()}"]}
                save_json(RESULTS / tool / "results.json", outs[tool])
    finally:
        netlab.down()
        print("=== netlab down ===", flush=True)

    reportmod.write_reports()
    reportmod.write_findings()
    print("\n=== reports written to bench/reports/ ===", flush=True)

    # Run health, last and loudest: a tool that was never measured is a harness
    # failure, not a score of zero, and must not be read off the scorecards as one.
    broken = [t for t, o in outs.items() if o.get("setup_failed") or not o.get("scenarios")]
    noted = [t for t, o in outs.items() if o.get("errors") and t not in broken]
    for t in noted:
        print(f"[{t}] ran with {len(outs[t]['errors'])} recorded error(s); see results/{t}/results.json", flush=True)
    if broken:
        print(f"\n!!! NOT MEASURED (setup failed): {', '.join(broken)}", flush=True)
        for t in broken:
            first = (outs[t].get("errors") or ["(no error recorded)"])[0]
            print(f"    {t}: {' '.join(first.split())[:300]}", flush=True)
        print("!!! Their scorecard columns are marked not-measured; fix the setup and rerun those tools.", flush=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
