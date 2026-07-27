"""Generate markdown scorecards + per-tool detail from results/<tool>/results.json."""

from __future__ import annotations

import json

from harness import REPORTS, RESULTS
from scenarios import build_scenarios

SYM = {"PASS": "✅ PASS", "PARTIAL": "🟡 PART", "FAIL": "❌ FAIL", "N/A": "⬜ N/A", "ERROR": "⚠️ ERR"}
SHORT = {"PASS": "✅", "PARTIAL": "🟡", "FAIL": "❌", "N/A": "⬜", "ERROR": "⚠️"}
TOOL_ORDER = ["picosnitch", "nethogs", "bandwhich", "opensnitch", "sniffnet", "littlesnitch", "bcc-baseline", "bcc-tcptop", "bpftrace", "sysdig"]
TOOL_LABEL = {
    "picosnitch": "picosnitch",
    "nethogs": "NetHogs",
    "bandwhich": "bandwhich",
    "opensnitch": "OpenSnitch",
    "sniffnet": "Sniffnet",
    "littlesnitch": "Little Snitch",
    "bcc-baseline": "BCC tcplife/tcpconnect",
    "bcc-tcptop": "BCC tcptop",
    "bpftrace": "bpftrace script",
    "sysdig": "Sysdig",
}


def _load():
    data = {}
    for p in sorted(RESULTS.glob("*/results.json")):
        try:
            d = json.loads(p.read_text())
            data[d["tool"]] = d
        except Exception as e:
            print(f"warning: skipping unreadable {p}: {e}")
    return data


# tools whose per-trial results are scored "best-of-N" (pass if any trial passes)
# because their extraction is inherently noisy — here, sniffnet via GUI OCR.
BESTOF = {"sniffnet"}
_ORD = {"PASS": 3, "PARTIAL": 2, "FAIL": 1, "ERROR": 0}


def _resolve(rec, kind, tool):
    """Return (verdict, flaky). For best-of-N tools, take the best trial verdict."""
    if rec is None:
        return "N/A", False
    if tool in BESTOF:
        vs = [t.get(kind) for t in rec.get("trials", []) if t.get(kind) not in (None, "N/A")]
        if not vs:
            return "N/A", False
        best = max(vs, key=lambda v: _ORD.get(v, -1))
        return best, len(set(vs)) > 1
    return rec.get(f"{kind}_final", "N/A"), rec.get(f"{kind}_flaky", False)


def _cell(rec, kind, tool):
    """kind = 'det' or 'bw'. Return (symbol, flaky)."""
    if rec is None:
        return "⬜", False
    v, flaky = _resolve(rec, kind, tool)
    return SHORT.get(v, "?"), flaky


BW_SUBTITLE = (
    "Scored on the bytes reported, independently of attribution. A configuration that measured the traffic but "
    "bucketed it as unknown instead of naming the process is still scored here on those bytes; that attribution "
    "miss is what the detection grid records as PARTIAL, so the two grids are meant to be read together."
)


def _matrix(data, kind, title, tools, subtitle=""):
    scn = build_scenarios()
    lines = [f"## {title}", ""]
    if subtitle:
        lines += [subtitle, ""]
    lines += ["| # | Scenario | " + " | ".join(TOOL_LABEL[t] for t in tools) + " |", "|---|---|" + "|".join(["---"] * len(tools)) + "|"]
    for s in scn:
        row = [s.sid, s.name]
        for t in tools:
            rec = data.get(t, {}).get("scenarios", {}).get(s.sid)
            sym, flaky = _cell(rec, kind, t)
            mark = ("*" if t in BESTOF else "⚡") if flaky else ""
            row.append(sym + mark)
        lines.append("| " + " | ".join(row) + " |")
    lines += ["", "Legend: ✅ PASS · 🟡 PARTIAL · ❌ FAIL · ⬜ N/A · ⚠️ error · ⚡ trials disagreed · \\* Sniffnet OCR, scored best of 5 trials", ""]
    return "\n".join(lines)


def _footnotes(data, tools):
    scn = {s.sid: s for s in build_scenarios()}
    lines = ["## Result notes", ""]
    for t in tools:
        d = data.get(t, {})
        sc = d.get("scenarios", {})
        items = []
        for sid, rec in sc.items():
            notes = []
            dv, dfl = _resolve(rec, "det", t)
            bv, bfl = _resolve(rec, "bw", t)
            if dv in ("PARTIAL", "FAIL") or bv in ("PARTIAL", "FAIL"):
                tr = [x for x in rec.get("trials", []) if "obs" in x]
                onote = tr[0]["obs"]["note"] if tr else ""
                ratio = ""
                for x in tr:
                    dtl = x.get("bw_detail", {})
                    for dcol in ("egress", "ingress"):
                        if isinstance(dtl, dict) and dcol in dtl:
                            ratio = f"{dcol} ratio≈{dtl[dcol]['ratio']}"
                            break
                    if ratio:
                        break
                seg = f"det={dv} bw={bv}"
                extra = "; ".join(x for x in [onote, ratio, scn[sid].note] if x)
                notes.append(f"    - **{sid} {scn[sid].name}** — {seg}. {extra}")
            if dfl or bfl:
                mk = "*" if t in BESTOF else "⚡"
                notes.append(f"    - **{sid}** {mk} inconsistent across trials (det {[x.get('det') for x in rec.get('trials', [])]}, bw {[x.get('bw') for x in rec.get('trials', [])]}).")
            items += notes
        if items:
            lines.append(f"- **{TOOL_LABEL[t]}**")
            lines += items
        if d.get("errors"):
            lines.append(f"    - _setup/runtime errors:_ {d['errors'][0][:200]}")
    return "\n".join(lines) + "\n"


def _fmtb(v):
    """Byte cell: '-' for absent, integers without a float tail."""
    if v is None:
        return "-"
    if isinstance(v, float) and v == int(v):
        return str(int(v))
    return str(v)


def _per_tool(data, tool):
    scn = {s.sid: s for s in build_scenarios()}
    d = data.get(tool, {})
    lines = [
        f"# {TOOL_LABEL.get(tool, tool)} — detailed results",
        "",
        f"- layer scored against: **{d.get('layer')}** ({'app-layer bytes' if d.get('layer') == 'socket' else 'wire bytes'})",
        "",
    ]
    ctrl = d.get("control")
    if ctrl:
        lines.append(
            f"- **control (bulk TCP download smoke transfer, separate from the s01 row):** "
            f"det={ctrl['det']} bw={ctrl['bw']} "
            f"(gt recv={ctrl['gt']['app_recv']}, reported recv={_fmtb(ctrl['obs']['recv'])})"
        )
    lines += ["", "| # | Scenario | Det | BW | GT app s/r | GT wire s/r | reported s/r | ratio | note |", "|---|---|---|---|---|---|---|---|---|"]
    any_flaky = False
    for sid, s in scn.items():
        rec = d.get("scenarios", {}).get(sid)
        if not rec:
            continue
        tr = [x for x in rec.get("trials", []) if "gt" in x]
        gt = tr[0]["gt"] if tr else {}
        obs = tr[0]["obs"] if tr else {}
        ratio = ""
        for x in tr:
            dtl = x.get("bw_detail", {})
            if isinstance(dtl, dict):
                for dcol in ("egress", "ingress"):
                    if dcol in dtl:
                        ratio = f"{dcol} {dtl[dcol]['ratio']}"
                        break
            if ratio:
                break
        dv, dfl = _resolve(rec, "det", tool)
        bv, bfl = _resolve(rec, "bw", tool)
        any_flaky = any_flaky or dfl or bfl
        mk = "*" if tool in BESTOF else "⚡"
        det = SYM.get(dv, "?") + (mk if dfl else "")
        bw = SYM.get(bv, "?") + (mk if bfl else "")
        gtapp = f"{gt.get('app_sent', 0)}/{gt.get('app_recv', 0)}"
        gtwire = f"{gt.get('wire_egress', 0)}/{gt.get('wire_ingress', 0)}"
        rep = f"{_fmtb(obs.get('sent'))}/{_fmtb(obs.get('recv'))}"
        note = (obs.get("note", "") or "")[:80]
        lines.append(f"| {sid} | {s.name} | {det} | {bw} | {gtapp} | {gtwire} | {rep} | {ratio} | {note} |")
    if any_flaky:
        lines += ["", "⚡/\\* rows: trials disagreed; the table shows the first trial's numbers, while the verdict combines all trials (best of 5 for Sniffnet)."]
    return "\n".join(lines) + "\n"


def _counts(d, tool):
    sc = d.get("scenarios", {})
    det = {sid: _resolve(r, "det", tool) for sid, r in sc.items()}
    bw = {sid: _resolve(r, "bw", tool) for sid, r in sc.items()}

    def c(m, v):
        return sum(1 for x, _ in m.values() if x == v)

    return {
        "det_pass": c(det, "PASS"),
        "det_part": c(det, "PARTIAL"),
        "det_fail": c(det, "FAIL"),
        "det_na": c(det, "N/A"),
        "det_err": c(det, "ERROR"),
        "bw_pass": c(bw, "PASS"),
        "bw_part": c(bw, "PARTIAL"),
        "bw_fail": c(bw, "FAIL"),
        "bw_na": c(bw, "N/A"),
        "bw_err": c(bw, "ERROR"),
        "flaky": sum(1 for sid in sc if det[sid][1] or bw[sid][1]),
    }


def write_findings():
    """The findings report (findings.md), computed from the data after the matrix."""
    REPORTS.mkdir(parents=True, exist_ok=True)
    data = _load()
    tools = [t for t in TOOL_ORDER if t in data]
    if not tools:
        print("no results")
        return
    scn = build_scenarios()
    C = {t: _counts(data[t], t) for t in tools}
    dates = sorted({d.get("run_date", "") for d in data.values() if d.get("run_date")})
    RUN_DATE = dates[0] if len(dates) == 1 else (f"{dates[0]} to {dates[-1]}" if dates else "date not recorded")
    # neutral ordering for the scoreboard: by detection then bandwidth PASS
    order = sorted(tools, key=lambda t: (-C[t]["det_pass"], -C[t]["bw_pass"]))

    REPO = "https://github.com/elesiuta/picosnitch/tree/master/bench"
    L = [
        "# Per-process network & bandwidth monitors on Linux\n",
        "<!-- --8<-- [start:findings] -->",
        "<!-- --8<-- [start:overview] -->",
        "A comparison of per-process (per-executable) network and bandwidth "
        "monitors on Linux, measuring **completeness** (is traffic seen and "
        "attributed to the right process) and **accuracy** (are the byte counts "
        "correct). Nine projects in ten configurations.\n",
        # NOTE: the host line below describes the recorded runs; update it if
        # re-running the matrix elsewhere.
        f"{len(scn)} scenarios × 5 trials, each configuration run in isolation on Ubuntu "
        f"26.04 (kernel 7.0) on a GCP e2-standard-4 (4 vCPUs, 16 GB), run {RUN_DATE}, "
        f"scored against tool-independent reference measurements. Detection = "
        f"*seen and attributed to the right process*; Bandwidth = *bytes within "
        f"±10% (PASS) / ±25% (PARTIAL)* of the tool's measurement layer. Method, "
        f"harness, versions, and how to reproduce: [the `bench/` directory]({REPO}).\n",
        "## Results summary\n",
        f"Each cell counts scenarios (of {len(scn)}). N/A marks a capability a "
        "configuration does not offer: OpenSnitch does no bandwidth accounting; the BCC "
        "utilities and the bpftrace script used here hook TCP only. Sniffnet has no "
        "per-process export, so its figures are read by OCR of its GUI and scored "
        "**best of 5 trials**: a scenario passes if any of its 5 trials passes, and `*` "
        "marks cells where its trials disagreed. Sniffnet also reports one combined "
        "per-program total, so the two full-duplex scenarios it cannot split by "
        "direction are N/A. The trial-disagreement column counts scenarios whose 5 "
        "trials did not all agree.\n",
        "| Tool | Detection: PASS / PART / FAIL / N/A | Bandwidth: PASS / PART / FAIL / N/A | Trial disagreement |",
        "|---|---|---|---|",
    ]
    for t in order:
        c = C[t]
        detfail = c["det_fail"] + c["det_err"]
        bwfail = c["bw_fail"] + c["bw_err"]
        L.append(f"| {TOOL_LABEL[t]} | **{c['det_pass']}** / {c['det_part']} / {detfail} / {c['det_na']} | **{c['bw_pass']}** / {c['bw_part']} / {bwfail} / {c['bw_na']} | {c['flaky']} |")

    # versions actually observed at run time, with how each was obtained
    if any(data[t].get("version") for t in order):
        L += [
            "",
            "## Versions",
            "",
            "Read from each installed tool during the run. Pinned entries are built or "
            "downloaded at a fixed version by the harness; distro packages are whatever "
            "the Ubuntu archive shipped on the run date and are recorded, not pinned.",
            "",
            "| Tool | Version observed | Source |",
            "|---|---|---|",
        ]
        for t in order:
            L.append(f"| {TOOL_LABEL[t]} | {data[t].get('version') or 'not recorded'} | {data[t].get('version_source') or 'not recorded'} |")

    # resource usage (present only when the run was profiled)
    res_rows = [(t, data[t].get("resources")) for t in order]
    if any(r and "pss_peak_mb" in r for _, r in res_rows):
        L += [
            "",
            "## Observed footprint\n",
            "Each configuration's whole process tree, sampled at 1 Hz across its "
            "session: the footprint observed under these specific configurations and "
            "capture scopes, not a controlled performance comparison. CPU is % of one "
            "core (can exceed 100% across cores). PSS (proportional set size) charges "
            "each shared page once, split across its sharers.\n",
            "| Tool | CPU mean % | CPU 95th pct % | PSS mean MB | PSS peak MB |",
            "|---|---|---|---|---|",
        ]
        for t, r in res_rows:
            if not r or "pss_peak_mb" not in r:
                continue
            L.append(f"| {TOOL_LABEL[t]} | {r['cpu_avg_pct']} | {r.get('cpu_p95_pct', '—')} | {r['pss_avg_mb']} | {r['pss_peak_mb']} |")

    # end of the overview (intro + scoreboard + resource usage) shown in the docs;
    # the per-scenario notes and ground-truth table below are full-report-only.
    L += ["", "<!-- --8<-- [end:overview] -->"]

    # per-scenario notes: the factual mechanism note each scenario carries
    notes = [f"- **{s.sid} {s.name}** — {s.note}" for s in scn if s.note]
    if notes:
        L += ["", "## Per-scenario notes\n"] + notes

    L += [
        "",
        "## Ground truth per scenario\n",
        "App bytes are the generators' own counts. Wire bytes include per-run "
        "variance (handshakes, retransmits); this table shows one session's "
        "capture, and each tool page records its own run's values.\n",
        "| # | Scenario | app bytes s/r | wire bytes s/r |",
        "|---|---|---|---|",
    ]
    for s in scn:
        tr = None
        for t in tools:
            rec = data[t].get("scenarios", {}).get(s.sid, {})
            for x in rec.get("trials", []):
                if x.get("gt", {}).get("app_sent", 0) or x.get("gt", {}).get("app_recv", 0):
                    tr = x["gt"]
                    break
            if tr:
                break
        if tr:
            L.append(f"| {s.sid} | {s.name} | {tr['app_sent']}/{tr['app_recv']} | {tr['wire_egress']}/{tr['wire_ingress']} |")
    L.append("<!-- --8<-- [end:findings] -->")
    (REPORTS / "findings.md").write_text("\n".join(L) + "\n")
    print(f"wrote findings.md ({len(order)} tools, {len(scn)} scenarios)")


def write_reports():
    REPORTS.mkdir(parents=True, exist_ok=True)
    data = _load()
    tools = [t for t in TOOL_ORDER if t in data]
    if not tools:
        print("no results found")
        return

    # detection scorecard ([start:grid]/[end:grid] wrap the grid for the docs page)
    (REPORTS / "scorecard-detection.md").write_text(
        "# Detection scorecard — *is the activity seen and attributed to the process?*\n\n"
        + "<!-- --8<-- [start:grid] -->\n"
        + _matrix(data, "det", "Detection", tools)
        + "\n"
        + "<!-- --8<-- [end:grid] -->\n"
        + _footnotes(data, tools)
    )
    # bandwidth scorecard
    (REPORTS / "scorecard-bandwidth.md").write_text(
        "# Bandwidth scorecard — *are the bytes measured accurately (±10% PASS / ±25% PARTIAL)?*\n\n"
        + "<!-- --8<-- [start:grid] -->\n"
        + _matrix(data, "bw", "Bandwidth accuracy", tools, subtitle=BW_SUBTITLE)
        + "\n"
        + "<!-- --8<-- [end:grid] -->\n"
        + _footnotes(data, tools)
    )
    # per-tool detail
    for t in tools:
        (REPORTS / f"tool-{t}.md").write_text(_per_tool(data, t))
    print(f"wrote {len(tools) + 2} report files to {REPORTS}")


if __name__ == "__main__":
    write_reports()
