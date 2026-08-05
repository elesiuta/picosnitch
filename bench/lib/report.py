"""Generate markdown scorecards + per-tool detail from results/<tool>/results.json."""

from __future__ import annotations

import json

from adapters import ADAPTERS
from harness import REPORTS, RESULTS
from scenarios import build_scenarios

SYM = {"PASS": "✅ PASS", "PARTIAL": "🟡 PART", "FAIL": "❌ FAIL", "N/A": "⬜ N/A", "ERROR": "⚠️ ERR"}
LAYER_REF = {
    "socket": "application bytes",
    "frame": "wire bytes (L3 + Ethernet header per packet)",
    "ippayload": "IP payload bytes (L3 minus the IP header per packet)",
}
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


def _broken(d):
    """Did this tool's setup fail, so it was never measured? Such a tool has no
    scenario rows at all, which must NOT read as a score of zero (or as N/A) --
    it is a harness/environment failure and is reported as one."""
    return bool(d.get("setup_failed")) or not d.get("scenarios")


def _resolve(rec, kind, tool):
    """Return (verdict, disagreement flag) for a cell."""
    if rec is None:
        return "N/A", False
    return rec.get(f"{kind}_final", "N/A"), rec.get(f"{kind}_flaky", False)


def _cell(rec, kind, tool):
    """kind = 'det' or 'bw'. Return (symbol, flaky)."""
    if rec is None:
        return "⬜", False
    v, flaky = _resolve(rec, kind, tool)
    return SHORT.get(v, "?"), flaky


BW_SUBTITLE = (
    "Scored on bytes reported, independently of attribution: a tool that measured the traffic but bucketed it as "
    "unknown is scored here on those bytes, and the detection grid records that miss as PARTIAL."
)


def _matrix(data, kind, title, tools, subtitle=""):
    scn = build_scenarios()
    lines = [f"## {title}", ""]
    if subtitle:
        lines += [subtitle, ""]
    lines += ["| # | Scenario | " + " | ".join(TOOL_LABEL[t] for t in tools) + " |", "|---|---|" + "|".join(["---"] * len(tools)) + "|"]
    broken = {t: _broken(data.get(t, {})) for t in tools}
    for s in scn:
        row = [s.sid, s.name]
        for t in tools:
            if broken[t]:  # never measured: not a blank N/A column
                row.append("⚠️")
                continue
            rec = data.get(t, {}).get("scenarios", {}).get(s.sid)
            sym, flaky = _cell(rec, kind, t)
            mark = "*" if flaky else ""
            row.append(sym + mark)
        lines.append("| " + " | ".join(row) + " |")
    lines += ["", "Legend: ✅ PASS · 🟡 PARTIAL · ❌ FAIL · ⬜ N/A · ⚠️ not measured (setup failed or unresolved trial) · \\* trials disagreed, see the note", ""]
    return "\n".join(lines)


def _evidence(rec, base):
    """What the tool reported, tallied over the trials: the generator it named,
    the bucket it used instead, or nothing. Trials run uniquely named copies of
    the generator, so a matched name is reported as the scenario's generator."""
    from collections import Counter

    c = Counter()
    for tr in rec.get("trials", []):
        nm = (tr.get("obs") or {}).get("names") or []
        if not nm:
            c["nothing"] += 1
            continue
        c[base if (tr.get("obs") or {}).get("attributed") else str(nm[0])] += 1
    return ", ".join(f"{k} x{v}" for k, v in c.most_common())


def _footnotes(data, tools):
    scn = {s.sid: s for s in build_scenarios()}
    lines = ["## Result notes", ""]
    for t in tools:
        d = data.get(t, {})
        sc = d.get("scenarios", {})
        items = []
        if _broken(d):  # setup failed: say so, rather than leaving an empty section
            items.append("    - **setup failed: this tool was never measured; the cells above are not results**")
        for sid, rec in sc.items():
            dv, dfl = _resolve(rec, "det", t)
            bv, bfl = _resolve(rec, "bw", t)
            if dv not in ("PARTIAL", "FAIL") and bv not in ("PARTIAL", "FAIL") and not (dfl or bfl):
                continue
            tr = [x for x in rec.get("trials", []) if "obs" in x]
            onote = tr[0]["obs"]["note"] if tr and not (dfl or bfl) else ""
            ratio = ""
            if not (dfl or bfl):  # a first-trial ratio would contradict a combined verdict
                for x in tr:
                    dtl = x.get("bw_detail", {})
                    for dcol in ("egress", "ingress"):
                        if isinstance(dtl, dict) and dcol in dtl:
                            ratio = f"{dcol} ratio≈{dtl[dcol]['ratio']}"
                            break
                    if ratio:
                        break
            seg = f"det={dv} bw={bv}. recorded: {_evidence(rec, scn[sid].exe)}"
            if dfl or bfl:
                seg += f" (det {[x.get('det') for x in rec.get('trials', [])]}, bw {[x.get('bw') for x in rec.get('trials', [])]})"
            extra = "; ".join(x for x in [onote, ratio] if x)
            items.append(f"    - **{sid} {scn[sid].name}**: {seg}. {extra}".rstrip().rstrip(".") + ".")
        errs = d.get("errors", [])
        if items or errs:  # errors need the tool header too, or they read as the previous tool's
            lines.append(f"- **{TOOL_LABEL[t]}**")
            lines += items
        for e in errs[:5]:
            lines.append(f"    - _run note:_ {' '.join(e.split())[:300]}")  # flattened: a traceback must stay one bullet
        if len(errs) > 5:
            lines.append(f"    - _run note:_ (+{len(errs) - 5} further notes not shown)")
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
    # a tool whose bandwidth_layer() overrides `layer` per scenario declares the
    # exception itself, so this line describes every row rather than most of them
    note = getattr(ADAPTERS.get(tool), "LAYER_NOTE", "")
    lines = [
        f"# {TOOL_LABEL.get(tool, tool)}: detailed results",
        "",
        f"- scored against: **{LAYER_REF.get(d.get('layer'), d.get('layer'))}**" + (f", {note}" if note else ""),
        "",
    ]
    if _broken(d):
        lines += ["> ⚠️ **Setup failed: this tool was never measured.** The harness recorded:"]
        lines += [f"> - {' '.join(e.split())[:500]}" for e in d.get("errors", [])] or ["> - (no error recorded)"]
        return "\n".join(lines) + "\n"
    ctrl = d.get("control")
    if ctrl:
        lines.append(f"- **control (separate from the s01 row):** det={ctrl['det']} bw={ctrl['bw']} (reference recv={ctrl['gt']['app_recv']}, reported recv={_fmtb(ctrl['obs']['recv'])})")
    lines += [
        "",
        "Rows show the first trial's numbers; verdicts combine all trials. \\* = trials disagreed.",
        "",
        "| # | Scenario | Det | BW | reference s/r | reported s/r | ratio | note |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for sid, s in scn.items():
        rec = d.get("scenarios", {}).get(sid)
        if not rec:
            continue
        tr = [x for x in rec.get("trials", []) if "gt" in x]
        obs = tr[0]["obs"] if tr else {}
        dtl = tr[0].get("bw_detail") if tr else None
        dtl = dtl if isinstance(dtl, dict) else {}
        # the reference actually scored against, per direction, at this tool's layer
        ref = "/".join(str(dtl[c]["ref"]) if c in dtl else "-" for c in ("egress", "ingress"))
        ratio = " ".join(f"{c} {dtl[c]['ratio']}" for c in ("egress", "ingress") if c in dtl)
        dv, dfl = _resolve(rec, "det", tool)
        bv, bfl = _resolve(rec, "bw", tool)
        det = SYM.get(dv, "?") + ("*" if dfl else "")
        bw = SYM.get(bv, "?") + ("*" if bfl else "")
        rep = f"{_fmtb(obs.get('sent'))}/{_fmtb(obs.get('recv'))}"
        note = (obs.get("note", "") or "")[:80]
        lines.append(f"| {sid} | {s.name} | {det} | {bw} | {ref} | {rep} | {ratio} | {note} |")
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
    ntrials = max((len(r.get("trials", [])) for d in data.values() for r in d.get("scenarios", {}).values()), default=0)
    RUN_DATE = max(d.get("run_date", "") for d in data.values())  # the date the run finished
    # neutral ordering for the scoreboard: by detection then bandwidth PASS
    order = sorted(tools, key=lambda t: (-C[t]["det_pass"], -C[t]["bw_pass"]))

    REPO = "https://github.com/elesiuta/picosnitch/tree/master/bench"
    L = [
        "# Per-process network & bandwidth monitors on Linux\n",
        "<!-- --8<-- [start:overview] -->",
        # hardcoded; update when running on another host
        f"{len(scn)} scenarios × {ntrials} trials on Ubuntu 26.04 (kernel 7.0) on a GCP "
        f"e2-standard-4 (4 vCPUs, 16 GB), run {RUN_DATE}. Detection = "
        f"*seen and attributed to the right process*; Bandwidth = *bytes within "
        f"±10% (PASS) / ±25% (PARTIAL)* of the reference for the tool's layer. Method, "
        f"harness, versions, and how to reproduce: [the `bench/` directory]({REPO}).\n",
        "## Results summary\n",
        f"Each cell counts scenarios (of {len(scn)}), unweighted; the scenarios are not "
        "equally important and the totals are not an overall ranking. N/A marks a missing "
        "capability or reference: OpenSnitch does no bandwidth accounting; the BCC utilities and "
        "the bpftrace script used here hook TCP only; Sniffnet reports one combined "
        "per-program total, so full-duplex scenarios it cannot split by direction are "
        "N/A; the loopback scenario has no wire measurement, so tools counting at a "
        "packet layer are N/A on its bandwidth.\n",
        "| Tool | Detection: PASS / PART / FAIL / N/A | Bandwidth: PASS / PART / FAIL / N/A | Trial disagreement |",
        "|---|---|---|---|",
    ]

    def err(n):
        return f" (+{n} ERR)" if n else ""

    for t in order:
        c = C[t]
        if _broken(data[t]):
            # never measured: printing 0 / 0 / 0 / 0 here would read as a tool that
            # scored nothing, which is exactly the wrong conclusion.
            L.append(f"| {TOOL_LABEL[t]} | ⚠️ **not measured (setup failed)** | ⚠️ **not measured (setup failed)** | — |")
            continue
        L.append(
            f"| {TOOL_LABEL[t]} | **{c['det_pass']}** / {c['det_part']} / {c['det_fail']} / {c['det_na']}{err(c['det_err'])} "
            f"| **{c['bw_pass']}** / {c['bw_part']} / {c['bw_fail']} / {c['bw_na']}{err(c['bw_err'])} | {c['flaky']} |"
        )

    # run health: a benchmark that could not set a tool up, or that recorded errors
    # while running one, must say so next to the numbers rather than in a log file.
    unhealthy = [t for t in order if _broken(data[t]) or data[t].get("errors")]
    if unhealthy:
        L += ["", "## Run health\n", "Recorded by the harness during this run. A tool that was never measured has no results in the tables above.\n"]
        for t in unhealthy:
            state = "**never measured** (setup failed)" if _broken(data[t]) else "ran, with notes"
            L.append(f"- **{TOOL_LABEL[t]}**: {state}")
            for e in data[t].get("errors", [])[:3]:
                L.append(f"    - {' '.join(e.split())[:300]}")

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
            "Each tool's whole process tree, sampled at 1 Hz across its session under its "
            "own capture scope; not a controlled performance comparison. CPU is % of one "
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
    notes = [f"- **{s.sid} {s.name}**: {s.note}" for s in scn if s.note]
    if notes:
        L += ["", "## Per-scenario notes\n"] + notes

    L += [
        "",
        "## Reference bytes per scenario\n",
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
        "# Detection scorecard: is the activity seen and attributed to the process?\n\n"
        + "<!-- --8<-- [start:grid] -->\n"
        + _matrix(data, "det", "Detection", tools)
        + "\n"
        + "<!-- --8<-- [end:grid] -->\n"
        + _footnotes(data, tools)
    )
    # bandwidth scorecard
    (REPORTS / "scorecard-bandwidth.md").write_text(
        "# Bandwidth scorecard: are the bytes measured accurately (±10% PASS, ±25% PARTIAL)?\n\n"
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
