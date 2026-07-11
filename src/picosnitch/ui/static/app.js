// SPDX-License-Identifier: GPL-3.0-or-later
// picosnitch web UI — vanilla ES2020, no build step, no external deps.
"use strict";

const $ = (id) => document.getElementById(id);
const PALETTE = [
  "#5e9eff", "#ff7a59", "#5fd1a0", "#f4c869", "#c98ad7", "#7fcde1",
  "#e26a6a", "#9bbf5e", "#d49ad6", "#7fc6c6", "#e9a06a", "#88a4d2",
  "#9d6f9c", "#5cb085", "#cc8a8a", "#7d97c2", "#a4cf85", "#bf8a5c",
];
const SVG_NS = "http://www.w3.org/2000/svg";

let META = null;
let CURRENT_TAB = "overview";
let LIVE_ES = null;
let LIVE_COUNT = 0;
let LIVE_SHOWN = 0;
const LIVE_RATE = { lastT: 0, lastN: 0, smoothed: 0 };
let LAST_DATA = null;
const HIDDEN_KEYS = new Set();
let SELECTED_KEY = null;  // explore drilldown selection
let OVERVIEW_METRIC = "r";  // "r" | "s" | "t"
let EXPLORE_METRIC = "r";
let AUTO_REFRESH_TIMER = null;
let SUMMARY_TIMER = null;
// Active time window. preset = one of META.ranges (e.g. "1h", "all");
// custom = a calendar/date selection serialised as unix-second bounds.
let CURRENT_RANGE = { kind: "preset", preset: "1h", from: 0, to: 0, label: "1h" };
let LAST_DRILLDOWN_KEY = null;
let LAST_DRILLDOWN_HTML = "";
// Daemon start time (unix seconds) derived from /api/meta. Used to keep
// the header uptime label ticking forward without a full meta refresh.
let DAEMON_START_TS = 0;
let DAEMON_RUNNING = false;
let UPTIME_TIMER = null;
let META_REFRESH_TIMER = null;

// ── theme toggle ─────────────────────────────────────────────────────
const THEME_KEY = "picosnitch-theme";
function applyTheme(t) {
  document.documentElement.dataset.theme = t;
  document.querySelectorAll("[data-theme-icon]").forEach((el) => {
    el.textContent = t === "light" ? "☀" : "☾";
  });
  document.querySelectorAll("[data-theme-label]").forEach((el) => {
    el.textContent = t === "light" ? "Light" : "Dark";
  });
}
function toggleTheme() {
  const sysLight = matchMedia("(prefers-color-scheme: light)").matches;
  const cur = document.documentElement.dataset.theme || (sysLight ? "light" : "dark");
  const next = cur === "light" ? "dark" : "light";
  try { localStorage.setItem(THEME_KEY, next); } catch (_) { /* ignore */ }
  applyTheme(next);
  // Re-render charts if visible — they cache colours from CSS vars.
  if (CURRENT_TAB === "explore" && LAST_DATA) renderExploreCharts();
  if (CURRENT_TAB === "overview" && LAST_DATA) renderOverviewChart();
}

// ── formatting helpers ───────────────────────────────────────────────
function fmtBytes(n) {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = Number(n);
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return v.toFixed(v < 10 && i > 0 ? 1 : 0) + " " + u[i];
}
function fmtInt(n) { return Number(n || 0).toLocaleString(); }
function fmtTimeShort(ts) { return new Date(ts * 1000).toLocaleString(); }
function fmtClock(ts) { return new Date(ts * 1000).toLocaleTimeString(); }
function fmtDay(ts) {
  const d = new Date(ts * 1000);
  return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}
function toDateInputValue(ts) {
  // <input type="date"> wants YYYY-MM-DD in the local timezone
  const d = new Date(ts * 1000);
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${y}-${m}-${day}`;
}
function dayStartTs(yyyy_mm_dd) {
  // Parse a YYYY-MM-DD as local-time midnight
  const [y, m, d] = yyyy_mm_dd.split("-").map(Number);
  return Math.floor(new Date(y, m - 1, d, 0, 0, 0).getTime() / 1000);
}
function fmtUptime(s) {
  if (!s || s < 0) return "—";
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  return `${m}m`;
}
// The host network namespace has a stable, well-known inode on Linux
// (4026531840). Container runtimes (Docker/Podman/LXC/k8s pods/...)
// allocate per-container netns with different inodes; we don't have a
// way to recover their human-readable names from the BPF capture (the
// daemon would need to look at /proc/*/ns/net symlinks at capture time
// and we don't store any name today), so we just label the host one
// and show "ns:<inode>" for everything else.
const NETNS_HOST_INODE = 4026531840;
function fmtNetns(inode) {
  if (inode === "" || inode === null || inode === undefined) return "(none)";
  const n = Number(inode);
  if (Number.isFinite(n) && n === NETNS_HOST_INODE) return "host";
  return `ns:${inode}`;
}
function shortenLabel(s, max) {
  if (s === null || s === undefined || s === "") return "(none)";
  s = safeText(s);
  if (s.length <= max) return s;
  return s.slice(0, max / 2 | 0) + "…" + s.slice(-(max / 2 | 0));
}
function safeText(s) {
  return String(s).replace(/[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u2069\ud800-\udfff\ufeff]/gu,"�");
}
function escapeHtml(s) {
  return safeText(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

// ── time window state ──────────────────────────────────────────────
function rangeQS() {
  // Returns the URL query fragment representing CURRENT_RANGE, suitable
  // for direct concatenation into an /api/* URL (no leading & or ?).
  if (CURRENT_RANGE.kind === "custom") {
    return `from=${CURRENT_RANGE.from}&to=${CURRENT_RANGE.to}`;
  }
  return `range=${encodeURIComponent(CURRENT_RANGE.preset || "1h")}`;
}
function rangeLabel() { return CURRENT_RANGE.label || CURRENT_RANGE.preset || "1h"; }
function onRangeChanged() {
  // Update every visible label that mirrors the current window.
  const lbl = rangeLabel();
  const sumEl = $("range-summary"); if (sumEl) sumEl.textContent = `last ${lbl}`;
  const expEl = $("explore-range"); if (expEl) expEl.textContent = lbl;
  document.querySelectorAll(".kpi-range").forEach((el) => { el.textContent = lbl; });
  // Highlight the active preset chip in the popover.
  document.querySelectorAll("#range-presets button").forEach((b) => {
    b.classList.toggle("active", CURRENT_RANGE.kind === "preset" && b.dataset.preset === CURRENT_RANGE.preset);
  });
  // drop drilldown cache so the next refresh re-renders
  LAST_DRILLDOWN_KEY = null;
  LAST_DRILLDOWN_HTML = "";
  if (CURRENT_TAB === "overview") refreshOverview();
  if (CURRENT_TAB === "explore") refreshExplore();
}
function setRangePreset(preset) {
  CURRENT_RANGE = { kind: "preset", preset, from: 0, to: 0, label: preset };
  closeRangePopover();
  onRangeChanged();
}
function setRangeCustom(fromTs, toTs) {
  CURRENT_RANGE = {
    kind: "custom",
    preset: null,
    from: fromTs,
    to: toTs,
    label: (fromTs && toTs) ? `${fmtDay(fromTs)} – ${fmtDay(toTs - 1)}` :
           fromTs ? `since ${fmtDay(fromTs)}` : `until ${fmtDay(toTs)}`,
  };
  closeRangePopover();
  onRangeChanged();
}
function closeRangePopover() {
  const pop = $("range-pop");
  if (pop) pop.removeAttribute("open");
}
function setupRangePopover() {
  const presetsEl = $("range-presets");
  if (presetsEl) {
    presetsEl.innerHTML = "";
    for (const r of META.ranges) {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "chip";
      b.dataset.preset = r;
      b.textContent = r;
      b.addEventListener("click", () => setRangePreset(r));
      presetsEl.appendChild(b);
    }
  }
  const apply = $("range-apply");
  if (apply) {
    apply.addEventListener("click", () => {
      const fromVal = $("range-from").value;
      const toVal = $("range-to").value;
      if (!fromVal && !toVal) return;
      // "To" is inclusive of the chosen day, so push it forward 1 day.
      const fromTs = fromVal ? dayStartTs(fromVal) : 0;
      let toTs;
      if (toVal) toTs = dayStartTs(toVal) + 86400;
      else if (fromVal) toTs = dayStartTs(fromVal) + 86400;
      else toTs = Math.floor(Date.now() / 1000);
      setRangeCustom(fromTs, toTs);
    });
  }
  // Pre-fill date inputs to today as a sensible default.
  const today = toDateInputValue(Math.floor(Date.now() / 1000));
  if ($("range-from")) $("range-from").value = today;
  // Close on outside click.
  document.addEventListener("click", (ev) => {
    const pop = $("range-pop");
    if (pop && pop.hasAttribute("open") && !pop.contains(ev.target)) {
      pop.removeAttribute("open");
    }
  });
}

// ── /api/meta ────────────────────────────────────────────────────────
function applyDaemonStatus(meta) {
  // status_state is one of "running" | "stopped" | "unknown". The text
  // is rendered as-is; the pulse switches between green/red/yellow.
  const state = meta.status_state || "unknown";
  $("status-text").textContent = meta.status || state;
  const pulse = $("status-pulse");
  if (pulse) {
    pulse.classList.toggle("pulse-bad",  state === "stopped");
    pulse.classList.toggle("pulse-warn", state === "unknown");
  }
  DAEMON_RUNNING = state === "running";
  DAEMON_START_TS = Number(meta.start_ts || 0);
  if (!DAEMON_START_TS && meta.uptime_seconds) {
    DAEMON_START_TS = Math.floor(Date.now() / 1000) - Number(meta.uptime_seconds);
  }
  updateUptimeLabel();
}
function updateUptimeLabel() {
  const el = $("meta-uptime");
  if (!el) return;
  if (!DAEMON_RUNNING || !DAEMON_START_TS) {
    el.textContent = "—";
    return;
  }
  const seconds = Math.max(0, Math.floor(Date.now() / 1000) - DAEMON_START_TS);
  el.textContent = fmtUptime(seconds);
}
async function refreshMeta() {
  try {
    const r = await fetch("/api/meta");
    if (!r.ok) return;
    const m = await r.json();
    META = m;
    $("status-db").textContent = fmtBytes(m.db_size_bytes || 0);
    $("meta-db").textContent = fmtBytes(m.db_size_bytes || 0);
    applyDaemonStatus(m);
  } catch (_) { /* ignore transient */ }
}
async function loadMeta() {
  const r = await fetch("/api/meta");
  META = await r.json();
  $("version").textContent = "v" + META.version;
  const fv = $("footer-version"); if (fv) fv.textContent = "picosnitch v" + META.version;
  $("status-db").textContent = fmtBytes(META.db_size_bytes || 0);
  $("meta-db").textContent = fmtBytes(META.db_size_bytes || 0);
  applyDaemonStatus(META);

  // Group-by sidebar
  const groupBy = $("group-by");
  groupBy.innerHTML = "";
  for (const [k, label] of Object.entries(META.dims)) {
    const li = document.createElement("li");
    li.textContent = label;
    li.dataset.dim = k;
    if (k === "exe") li.classList.add("active");
    li.addEventListener("click", () => selectDim(k));
    groupBy.appendChild(li);
  }

  // Where-filter dim selector
  const whereSel = $("where");
  for (const [k, label] of Object.entries(META.dims)) {
    const opt = document.createElement("option");
    opt.value = k; opt.textContent = label;
    whereSel.appendChild(opt);
  }

  // Build the range popover from META.ranges and apply the initial label.
  setupRangePopover();
  onRangeChanged();
}

// ── tab switching ────────────────────────────────────────────────────
function showTab(name) {
  CURRENT_TAB = name;
  document.querySelectorAll("#view-tabs .tab").forEach((el) => {
    el.classList.toggle("active", el.dataset.tab === name);
  });
  document.querySelectorAll(".tab-panel").forEach((el) => {
    el.classList.toggle("active", el.id === "tab-" + name);
  });
  // sidebar group-only sections only show on Explore
  document.querySelectorAll(".group-only").forEach((el) => {
    el.style.display = (name === "explore") ? "" : "none";
  });
  $("page-title").textContent = ({
    overview: "Overview",
    explore: "Explore",
    live: "Live feed",
  }[name]) || "picosnitch";
  if (name === "overview") refreshOverview();
  if (name === "explore") refreshExplore();
}

// ── group-by selection (sidebar) ─────────────────────────────────────
function selectDim(dim) {
  document.querySelectorAll("#group-by li").forEach((el) => {
    el.classList.toggle("active", el.dataset.dim === dim);
  });
  $("explore-group").textContent = (META && META.dims[dim]) || dim;
  refreshExplore();
}
function currentDim() {
  const active = document.querySelector("#group-by li.active");
  return (active && active.dataset.dim) || "exe";
}

// ── /api/summary KPIs ────────────────────────────────────────────────
async function refreshSummary() {
  document.querySelectorAll(".kpi-range").forEach((el) => { el.textContent = rangeLabel(); });
  try {
    const r = await fetch("/api/summary?" + rangeQS());
    const d = await r.json();
    $("kpi-sent").textContent = fmtBytes(d.sent);
    $("kpi-recv").textContent = fmtBytes(d.recv);
    $("kpi-conns").textContent = fmtInt(d.connections);
    $("kpi-procs").textContent = fmtInt(d.executables);
    $("kpi-netns").textContent = fmtInt(d.netns);
  } catch (_) { /* ignore transient */ }
}

// ── chart rendering (shared by Overview + Explore) ───────────────────
function valueAt(arr, kind, j) {
  return kind === "t" ? (arr.s[j] + arr.r[j]) : arr[kind][j];
}
function metricLabel(kind) {
  return kind === "s" ? "Bytes sent" : kind === "t" ? "Total bytes" : "Bytes received";
}
function renderChartInto(targetEl, data, kind, opts) {
  // kind: "s" (sent), "r" (received), or "t" (total). One polyline per series.
  // opts: { height, showAxis, gridlines, selectable, area, stacked }
  //   area    : draw a semi-transparent fill below each series line
  //   stacked : stack series cumulatively (implies area)
  opts = opts || {};
  const H = opts.height || 220;
  const showAxis = opts.showAxis !== false;
  const stacked = !!opts.stacked;
  const area = stacked || !!opts.area;
  targetEl.innerHTML = "";
  targetEl.style.position = "relative";

  const series = data.series;
  const allKeys = Object.keys(series);
  // visible keys are what we render and stack — hidden keys are skipped entirely
  // so toggling a series in the legend collapses the stack instead of leaving a gap
  const keys = allKeys.filter((k) => !HIDDEN_KEYS.has(k));
  if (allKeys.length === 0) {
    targetEl.innerHTML = '<div class="muted" style="padding:20px;">no data</div>';
    return;
  }

  // unify the time axis across every series so stacked areas line up at every t
  const tSet = new Set();
  for (const k of allKeys) for (const t of series[k].t) tSet.add(t);
  const tAxis = [...tSet].sort((a, b) => a - b);
  let minT = tAxis.length ? tAxis[0] : 0;
  let maxT = tAxis.length ? tAxis[tAxis.length - 1] : 0;
  if (maxT === minT) maxT = minT + (data.bucket || 60);

  // for each visible series, build a value-at-t lookup aligned to tAxis
  const seriesVals = {};
  for (const k of keys) {
    const arr = series[k];
    const tToV = new Map();
    for (let j = 0; j < arr.t.length; j++) tToV.set(arr.t[j], valueAt(arr, kind, j));
    seriesVals[k] = tAxis.map((t) => tToV.get(t) || 0);
  }

  // compute y bounds: for stacked, the max stack height; otherwise max single value
  let maxY = 0;
  if (stacked) {
    for (let i = 0; i < tAxis.length; i++) {
      let s = 0;
      for (const k of keys) s += seriesVals[k][i];
      if (s > maxY) maxY = s;
    }
  } else {
    for (const k of keys) for (const v of seriesVals[k]) if (v > maxY) maxY = v;
  }
  if (maxY === 0) maxY = 1;

  const W = targetEl.clientWidth || 800;
  const padL = showAxis ? 50 : 6;
  const padR = 10;
  const padT = 10;
  const padB = showAxis ? 22 : 6;
  const innerW = W - padL - padR;
  const innerH = H - padT - padB;
  const x = (t) => padL + ((t - minT) / (maxT - minT)) * innerW;
  const y = (v) => padT + innerH - (v / maxY) * innerH;

  const styles = getComputedStyle(document.documentElement);
  const gridColor = styles.getPropertyValue("--chart-grid").trim() || "#2a313c";
  const mutedColor = styles.getPropertyValue("--muted").trim() || "#889099";

  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.setAttribute("preserveAspectRatio", "none");
  svg.setAttribute("height", H);
  svg.setAttribute("width", "100%");

  // gridlines
  const grid = document.createElementNS(SVG_NS, "g");
  grid.setAttribute("stroke", gridColor); grid.setAttribute("stroke-width", "1");
  for (let i = 0; i <= 4; i++) {
    const yy = padT + (innerH * i / 4);
    const line = document.createElementNS(SVG_NS, "line");
    line.setAttribute("x1", padL); line.setAttribute("x2", W - padR);
    line.setAttribute("y1", yy); line.setAttribute("y2", yy);
    grid.appendChild(line);
    if (showAxis) {
      const lbl = document.createElementNS(SVG_NS, "text");
      lbl.setAttribute("x", padL - 4); lbl.setAttribute("y", yy + 4);
      lbl.setAttribute("fill", mutedColor); lbl.setAttribute("font-size", "10");
      lbl.setAttribute("text-anchor", "end");
      lbl.textContent = fmtBytes(maxY * (1 - i / 4));
      grid.appendChild(lbl);
    }
  }
  svg.appendChild(grid);

  if (showAxis) {
    const xlbl1 = document.createElementNS(SVG_NS, "text");
    xlbl1.setAttribute("x", padL); xlbl1.setAttribute("y", H - 4);
    xlbl1.setAttribute("fill", mutedColor); xlbl1.setAttribute("font-size", "10");
    xlbl1.textContent = fmtTimeShort(minT);
    svg.appendChild(xlbl1);
    const xlbl2 = document.createElementNS(SVG_NS, "text");
    xlbl2.setAttribute("x", W - padR); xlbl2.setAttribute("y", H - 4);
    xlbl2.setAttribute("fill", mutedColor); xlbl2.setAttribute("font-size", "10");
    xlbl2.setAttribute("text-anchor", "end");
    xlbl2.textContent = fmtTimeShort(maxT);
    svg.appendChild(xlbl2);
  }

  // build each series — both stroke and (optional) area fill
  const seriesPoints = [];
  const hasSelection = SELECTED_KEY !== null && keys.includes(SELECTED_KEY) && opts.selectable;
  const dimColor = (styles.getPropertyValue("--muted-2").trim() || mutedColor || "#445");
  // running stack baseline (lower envelope) — only used for stacked mode
  const stackLow = stacked ? new Array(tAxis.length).fill(0) : null;

  // map each visible key back to its index in the original keys order so
  // colors stay stable when other series are toggled hidden
  keys.forEach((k) => {
    const origIdx = allKeys.indexOf(k);
    const baseColor = PALETTE[origIdx % PALETTE.length];
    const isSelected = hasSelection && k === SELECTED_KEY;
    const color = (hasSelection && !isSelected) ? dimColor : baseColor;
    const vals = seriesVals[k];
    const recorded = [];
    const linePts = [];        // top of band for this series
    const lowPts = [];         // bottom of band (matches stack baseline or 0)
    for (let j = 0; j < tAxis.length; j++) {
      const tj = tAxis[j];
      const xPx = x(tj);
      const lowV = stacked ? stackLow[j] : 0;
      const topV = lowV + vals[j];
      const yTop = y(topV);
      const yLow = y(lowV);
      linePts.push(xPx + "," + yTop);
      lowPts.push(xPx + "," + yLow);
      recorded.push({ t: tj, v: vals[j], stackV: topV, xPx, yPx: yTop });
    }
    if (linePts.length === 0) return;
    if (area) {
      const polygon = document.createElementNS(SVG_NS, "polygon");
      // top of band followed by reversed bottom to close the path
      polygon.setAttribute("points", linePts.concat(lowPts.slice().reverse()).join(" "));
      polygon.setAttribute("fill", color);
      polygon.setAttribute("fill-opacity", isSelected ? "0.35" : (hasSelection && !isSelected ? "0.08" : "0.22"));
      polygon.setAttribute("stroke", "none");
      polygon.dataset.key = k;
      svg.appendChild(polygon);
    }
    const poly = document.createElementNS(SVG_NS, "polyline");
    poly.setAttribute("fill", "none");
    poly.setAttribute("stroke", color);
    poly.setAttribute("stroke-width", isSelected ? "2.6" : "1.6");
    if (hasSelection && !isSelected) poly.setAttribute("opacity", "0.55");
    poly.setAttribute("points", linePts.join(" "));
    poly.dataset.key = k;
    svg.appendChild(poly);
    seriesPoints.push({ key: k, color: baseColor, pts: recorded });
    if (stacked) for (let j = 0; j < tAxis.length; j++) stackLow[j] += vals[j];
  });

  // hover guide + per-series dots
  const guide = document.createElementNS(SVG_NS, "line");
  guide.setAttribute("stroke", mutedColor); guide.setAttribute("stroke-width", "0.5");
  guide.setAttribute("stroke-dasharray", "2,2");
  guide.setAttribute("y1", padT); guide.setAttribute("y2", padT + innerH);
  guide.setAttribute("x1", -10); guide.setAttribute("x2", -10);
  svg.appendChild(guide);
  const dots = [];
  for (const _ of seriesPoints) {
    const c = document.createElementNS(SVG_NS, "circle");
    c.setAttribute("r", "3"); c.setAttribute("fill", "transparent");
    c.setAttribute("stroke", "rgba(0,0,0,0.4)"); c.setAttribute("stroke-width", "0.5");
    svg.appendChild(c); dots.push(c);
  }
  targetEl.appendChild(svg);

  // docked tooltip pinned to the top-right of the chart container, always
  // visible on hover; lists every visible series sorted by value and
  // highlights the one nearest the cursor (smallest |y - hover y|).
  const tip = document.createElement("div");
  tip.className = "chart-tooltip chart-tooltip-docked";
  tip.style.display = "none";
  targetEl.appendChild(tip);

  svg.addEventListener("mousemove", (ev) => {
    const rect = svg.getBoundingClientRect();
    const scaleX = rect.width / W;
    const scaleY = rect.height / H;
    const mxView = (ev.clientX - rect.left) / scaleX;
    const myView = (ev.clientY - rect.top) / scaleY;
    if (mxView < padL || mxView > W - padR) {
      tip.style.display = "none";
      guide.setAttribute("x1", -10); guide.setAttribute("x2", -10);
      dots.forEach((d) => d.setAttribute("fill", "transparent"));
      return;
    }
    const tHover = minT + ((mxView - padL) / innerW) * (maxT - minT);
    let snapX = mxView;
    let snapT = tHover;
    let nearestIdx = -1;
    let nearestDy = Infinity;
    const rowsForTip = [];
    seriesPoints.forEach((sp, idx) => {
      let best = null, bestDist = Infinity;
      for (const p of sp.pts) {
        const d = Math.abs(p.t - tHover);
        if (d < bestDist) { bestDist = d; best = p; }
      }
      if (best) {
        dots[idx].setAttribute("cx", best.xPx);
        dots[idx].setAttribute("cy", best.yPx);
        dots[idx].setAttribute("fill", sp.color);
        if (idx === 0) { snapX = best.xPx; snapT = best.t; }
        const dy = Math.abs(best.yPx - myView);
        if (dy < nearestDy) { nearestDy = dy; nearestIdx = idx; }
        rowsForTip.push({ idx, key: sp.key, color: sp.color, value: best.v });
      }
    });
    guide.setAttribute("x1", snapX); guide.setAttribute("x2", snapX);
    rowsForTip.sort((a, b) => b.value - a.value);
    const linesHtml = rowsForTip.map((row) => {
      const cls = row.idx === nearestIdx ? "tip-row tip-row-active" : "tip-row";
      return `<div class="${cls}">`
        + `<span class="legend-swatch" style="background:${row.color}"></span>`
        + `<span class="tip-key">${escapeHtml(shortenLabel(row.key, 36))}</span>`
        + `<span class="tip-val">${fmtBytes(row.value)}</span>`
        + `</div>`;
    }).join("");
    tip.innerHTML = `<div class="tip-time muted">${fmtTimeShort(snapT)}</div>${linesHtml}`;
    tip.style.display = "block";
  });
  svg.addEventListener("mouseleave", () => {
    tip.style.display = "none";
    guide.setAttribute("x1", -10); guide.setAttribute("x2", -10);
    dots.forEach((d) => d.setAttribute("fill", "transparent"));
  });
}

// ── Overview tab ────────────────────────────────────────────────────
async function refreshOverview() {
  await refreshSummary();
  // Top-5 executables for the chosen range, used for chart + legend + table.
  const url = `/api/aggregate?dim=exe&${rangeQS()}&limit=5`;
  try {
    const r = await fetch(url);
    LAST_DATA = await r.json();
  } catch (_) { return; }
  renderOverviewChart();
  renderOverviewLegend();
  renderOverviewTable();
}
function renderOverviewChart() {
  if (!LAST_DATA) return;
  $("overview-chart-title").textContent = `${metricLabel(OVERVIEW_METRIC)} · top contributors`;
  // overview = passive view: stacked area lays the top contributors on top
  // of each other so crossover never looks like noise
  renderChartInto($("overview-chart"), LAST_DATA, OVERVIEW_METRIC, { height: 200, stacked: true });
}
function renderOverviewLegend() {
  const target = $("overview-legend");
  target.innerHTML = "";
  const totals = (LAST_DATA && LAST_DATA.totals) || {};
  Object.keys(totals).forEach((k, i) => {
    const row = document.createElement("div");
    row.className = "legend-row";
    const sw = document.createElement("span");
    sw.className = "swatch";
    sw.style.background = PALETTE[i % PALETTE.length];
    const name = document.createElement("span");
    name.className = "name";
    name.textContent = shortenLabel(k, 40);
    const val = document.createElement("span");
    val.className = "val";
    const t = totals[k];
    const v = OVERVIEW_METRIC === "s" ? t.send : OVERVIEW_METRIC === "t" ? (t.send + t.recv) : t.recv;
    val.textContent = fmtBytes(v);
    row.appendChild(sw); row.appendChild(name); row.appendChild(val);
    target.appendChild(row);
  });
}
function renderOverviewTable() {
  const tbody = document.querySelector("#overview-table tbody");
  tbody.innerHTML = "";
  const totals = (LAST_DATA && LAST_DATA.totals) || {};
  Object.keys(totals).forEach((k) => {
    const tr = document.createElement("tr");
    const t1 = document.createElement("td"); t1.textContent = shortenLabel(k, 60);
    const t2 = document.createElement("td"); t2.className = "right"; t2.textContent = fmtInt(totals[k].connections || 0);
    const t3 = document.createElement("td"); t3.className = "right"; t3.textContent = fmtBytes(totals[k].send);
    const t4 = document.createElement("td"); t4.className = "right"; t4.textContent = fmtBytes(totals[k].recv);
    tr.appendChild(t1); tr.appendChild(t2); tr.appendChild(t3); tr.appendChild(t4);
    tbody.appendChild(tr);
  });
}

// ── Explore tab ─────────────────────────────────────────────────────
async function loadWhereOptions() {
  const w = $("where").value;
  const sel = $("whereis");
  sel.innerHTML = '<option value="">(any)</option>';
  if (!w) return;
  const r = await fetch("/api/distinct?dim=" + encodeURIComponent(w));
  const vals = await r.json();
  for (const v of vals) {
    const opt = document.createElement("option");
    opt.value = v; opt.textContent = shortenLabel(v, 80);
    sel.appendChild(opt);
  }
}
async function refreshExplore() {
  const dim = currentDim();
  const where = $("where").value;
  const whereis = $("whereis").value;
  $("explore-group").textContent = (META && META.dims[dim]) || dim;
  $("explore-range").textContent = rangeLabel();
  let url = `/api/aggregate?dim=${encodeURIComponent(dim)}&${rangeQS()}`;
  if (where && whereis) url += `&where=${encodeURIComponent(where)}&whereis=${encodeURIComponent(whereis)}`;
  try {
    const r = await fetch(url);
    LAST_DATA = await r.json();
  } catch (_) { return; }
  // drop stale selection when the underlying dataset no longer has it
  if (SELECTED_KEY !== null && !(SELECTED_KEY in (LAST_DATA.totals || {}))) {
    SELECTED_KEY = null;
    renderDrilldownEmpty();
  } else if (SELECTED_KEY !== null) {
    loadDrilldown(SELECTED_KEY, { silent: true });
  }
  renderExploreCharts();
  renderExploreTable();
}
function renderExploreCharts() {
  if (!LAST_DATA) return;
  $("explore-chart-title").textContent = `${metricLabel(EXPLORE_METRIC)} · ${LAST_DATA.label}`;
  renderChartInto($("chart-main"), LAST_DATA, EXPLORE_METRIC, { height: 240, selectable: true });
}
function renderExploreTable() {
  if (!LAST_DATA) return;
  $("totals-head").textContent = LAST_DATA.label;
  const tbody = document.querySelector("#totals tbody");
  tbody.innerHTML = "";
  const totals = LAST_DATA.totals || {};
  Object.keys(totals).forEach((k, i) => {
    const tr = document.createElement("tr");
    tr.classList.add("legend-row");
    if (HIDDEN_KEYS.has(k)) tr.classList.add("hidden");
    if (k === SELECTED_KEY) tr.classList.add("selected");
    tr.dataset.key = k;
    tr.title = (k || "(none)") + "\nclick to drill down  ·  shift+click to hide in chart";
    tr.addEventListener("click", (ev) => {
      if (ev.shiftKey) { toggleSeries(k); return; }
      selectRow(k);
    });
    const td1 = document.createElement("td");
    const sw = document.createElement("span");
    sw.className = "legend-swatch";
    sw.style.background = PALETTE[i % PALETTE.length];
    td1.appendChild(sw);
    td1.appendChild(document.createTextNode(shortenLabel(k, 100)));
    const td2 = document.createElement("td"); td2.className = "right"; td2.textContent = fmtBytes(totals[k].send);
    const td3 = document.createElement("td"); td3.className = "right"; td3.textContent = fmtBytes(totals[k].recv);
    tr.appendChild(td1); tr.appendChild(td2); tr.appendChild(td3);
    tbody.appendChild(tr);
  });
}
function selectRow(k) {
  SELECTED_KEY = (SELECTED_KEY === k) ? null : k;
  renderExploreCharts();
  renderExploreTable();
  if (SELECTED_KEY === null) {
    renderDrilldownEmpty();
  } else {
    loadDrilldown(SELECTED_KEY);
  }
}
function renderDrilldownEmpty() {
  const pane = $("drilldown-pane");
  if (!pane) return;
  pane.innerHTML = '<div class="drilldown-empty muted">Click a row in the table to drill down.</div>';
  LAST_DRILLDOWN_KEY = null;
  LAST_DRILLDOWN_HTML = "";
}
async function loadDrilldown(value, opts) {
  // opts.silent  : do not show "Loading..." placeholder; used during
  //                periodic auto-refresh so the panel never flashes.
  opts = opts || {};
  const pane = $("drilldown-pane");
  if (!pane) return;
  const dim = currentDim();
  if (!opts.silent) {
    pane.innerHTML = '<div class="drilldown-empty muted">Loading…</div>';
  }
  let data;
  try {
    const r = await fetch(`/api/drilldown?dim=${encodeURIComponent(dim)}&value=${encodeURIComponent(value)}&${rangeQS()}`);
    if (!r.ok) throw new Error("http " + r.status);
    data = await r.json();
  } catch (e) {
    if (!opts.silent) {
      pane.innerHTML = `<div class="drilldown-empty muted">Error: ${escapeHtml(String(e))}</div>`;
    }
    return;
  }
  if (SELECTED_KEY !== value) return;  // selection changed mid-flight
  renderDrilldown(data);
}
function renderProcessInfo(data) {
  // Pick labels for each process level (e/p/g) based on which dim was
  // drilled into. Schema: e = process, p = parent, g = grandparent.
  //   drill on e.* (or non-process dim): e=Process, p=Parent, g=Grandparent
  //   drill on p.*: p=Process, e=Children (of p), g=Parent (of p)
  //   drill on g.*: g=Process, p=Children (of g), e=Grandchildren (of g)
  const dim = data.dim || "";
  let levels;
  if (dim.startsWith("gp")) {
    levels = [["g", "Process"], ["p", "Children"], ["e", "Grandchildren"]];
  } else if (dim.startsWith("p")) {
    levels = [["p", "Process"], ["e", "Children"], ["g", "Parent"]];
  } else {
    levels = [["e", "Process"], ["p", "Parent"], ["g", "Grandparent"]];
  }
  const fields = [
    ["name",    "Name"],
    ["cmdline", "Command"],
    ["exe",     "Exe"],
    ["sha256",  "SHA256"],
  ];
  const pi = data.process_info || {};
  const sections = levels.map(([alias, label]) => {
    const info = pi[alias] || {};
    // skip a level entirely if every field is empty (e.g. the process
    // genuinely has no recorded grandparent for this selection)
    const hasAny = fields.some(([f]) => (info[f] || []).length > 0);
    if (!hasAny) return "";
    const rows = fields.map(([f, fLabel]) => {
      const vals = info[f] || [];
      let body;
      if (vals.length === 0) {
        body = `<span class="dd-pinfo-v muted">\u2014</span>`;
      } else {
        // Don't shortenLabel here -- the column is narrow and the value
        // is the whole point; let it wrap via overflow-wrap: anywhere.
        body = vals.map((v) => `<span class="dd-pinfo-v" title="${escapeHtml(v)}">${escapeHtml(v)}</span>`).join("");
      }
      return `<div class="dd-pinfo-row"><span class="dd-pinfo-k">${escapeHtml(fLabel)}</span><div class="dd-pinfo-vs">${body}</div></div>`;
    }).join("");
    return `<details class="dd-breakdown"><summary>${escapeHtml(label)}</summary>`
      + `<div class="dd-pinfo">${rows}</div></details>`;
  }).filter((s) => s).join("");
  if (!sections) return "";
  return `<div class="dd-section dd-breakdowns">${sections}</div>`;
}
function renderDrilldown(data) {
  const pane = $("drilldown-pane");
  if (!pane) return;
  const t = data.totals || {};
  const sparkSvg = drilldownSparkline(data.sparkline || [], 320, 60, EXPLORE_METRIC);
  // Sent + Received first, side-by-side in the top row, so the throughput
  // pair reads as a unit. "Last seen" is intentionally omitted (the
  // sparkline already shows recency); only "First seen" stays.
  const meta = [
    ["Sent",        fmtBytes(t.sent), "emph"],
    ["Received",    fmtBytes(t.recv), "emph"],
    ["Connections", fmtInt(t.connections)],
    ["Domains",     fmtInt(t.domains)],
    ["Addresses",   fmtInt(t.addresses)],
    ["UIDs",        fmtInt(t.uids)],
    ["Net ns",      fmtInt(t.netns)],
    ["First seen",  t.first_seen ? fmtTimeShort(t.first_seen) : "—"],
  ];
  const metaHtml = meta.map(([k, v, cls]) =>
    `<div class="meta-cell${cls ? " meta-" + cls : ""}"><span class="meta-k">${escapeHtml(k)}</span><span class="meta-v">${escapeHtml(v)}</span></div>`
  ).join("");
  const recentHtml = (data.recent || []).map((c) => {
    const dest = c.domain || (c.raddr + (c.rport ? ":" + c.rport : ""));
    return `<li><span class="dd-time muted">${escapeHtml(fmtClock(c.t))}</span>`
      + `<span class="dd-name" title="${escapeHtml(dest)}">${escapeHtml(shortenLabel(dest, 30))}</span>`
      + `<span class="dd-meta muted">↑${fmtBytes(c.send)} ↓${fmtBytes(c.recv)}</span></li>`;
  }).join("") || '<li class="muted">no recent connections</li>';
  // Per-distinct-count breakdowns as collapsible <details> blocks under the meta-grid.
  const breakdownSpec = [
    { key: "uid",     title: "By UID",     count: t.uids,      formatter: (k) => k === "" ? "(none)" : `uid ${k}` },
    { key: "netns",   title: "By net ns",  count: t.netns,     formatter: fmtNetns },
    { key: "domain",  title: "By domain",  count: t.domains,   formatter: (k) => k || "(none)" },
    { key: "address", title: "By address", count: t.addresses, formatter: (k) => k || "(none)" },
  ];
  const breakdowns = data.breakdowns || {};
  const breakdownsHtml = breakdownSpec.map((spec) => {
    const rows = breakdowns[spec.key] || [];
    if (rows.length === 0) return "";
    const items = rows.map((r) => {
      const label = spec.formatter(r.key);
      return `<li><span class="dd-name" title="${escapeHtml(label)}">${escapeHtml(shortenLabel(label, 38))}</span>`
        + `<span class="dd-meta muted">${fmtBytes(r.send + r.recv)} \u00b7 ${fmtInt(r.count)}</span></li>`;
    }).join("");
    const countLabel = spec.count !== undefined ? ` <span class="muted">(${fmtInt(spec.count)})</span>` : "";
    return `<details class="dd-breakdown"><summary>${escapeHtml(spec.title)}${countLabel}</summary>`
      + `<ul class="dd-list">${items}</ul></details>`;
  }).join("");
  const pinfoHtml = renderProcessInfo(data);
  const html = `
    <div class="dd-header">
      <div class="dd-label muted">${escapeHtml(data.label)}</div>
      <div class="dd-title" title="${escapeHtml(data.value || "")}">${escapeHtml(shortenLabel(data.value || "(none)", 60))}</div>
      <button class="btn dd-close" title="Clear selection">×</button>
    </div>
    <div class="dd-spark">${sparkSvg}</div>
    <div class="meta-grid">${metaHtml}</div>
    ${breakdownsHtml ? `<div class="dd-section dd-breakdowns">${breakdownsHtml}</div>` : ""}
    ${pinfoHtml}
    <details class="dd-breakdown">
      <summary>Recent connections</summary>
      <ul class="dd-list">${recentHtml}</ul>
    </details>
  `;
  // Skip DOM swap when nothing changed so open <details> survive auto-refresh.
  const cacheKey = (data.dim || "") + "\x00" + (data.value || "");
  if (cacheKey === LAST_DRILLDOWN_KEY && html === LAST_DRILLDOWN_HTML) return;
  // Capture which <details> the user has open (by summary text) and
  // restore them after the swap; explicitly close the rest so baked-in
  // open attributes don't reopen sections the user closed.
  const openSummaries = new Set();
  pane.querySelectorAll("details.dd-breakdown").forEach((d) => {
    const s = d.querySelector("summary");
    if (s && d.hasAttribute("open")) openSummaries.add(s.textContent);
  });
  const scrollY = pane.scrollTop;
  pane.innerHTML = html;
  pane.querySelectorAll("details.dd-breakdown").forEach((d) => {
    const s = d.querySelector("summary");
    if (!s) return;
    if (openSummaries.has(s.textContent)) d.setAttribute("open", "");
    else d.removeAttribute("open");
  });
  // Restore scroll AFTER toggling <details> so layout has its final height first.
  pane.scrollTop = scrollY;
  LAST_DRILLDOWN_KEY = cacheKey;
  LAST_DRILLDOWN_HTML = html;
  const closeBtn = pane.querySelector(".dd-close");
  if (closeBtn) closeBtn.addEventListener("click", () => selectRow(SELECTED_KEY));
}
function drilldownSparkline(points, w, h, metric) {
  if (!points || points.length === 0) {
    return `<svg viewBox="0 0 ${w} ${h}" width="100%" height="${h}"></svg>`;
  }
  // metric: "r" (recv), "s" (sent), or "t" (total). Falls back to "r".
  const pick = (p) => metric === "s" ? p.s : metric === "t" ? (p.s + p.r) : p.r;
  let minT = Infinity, maxT = -Infinity, maxV = 0;
  for (const p of points) {
    if (p.t < minT) minT = p.t;
    if (p.t > maxT) maxT = p.t;
    const v = pick(p);
    if (v > maxV) maxV = v;
  }
  if (maxT === minT) maxT = minT + 60;
  if (maxV === 0) maxV = 1;
  const padX = 4, padY = 6;
  const innerW = w - padX * 2, innerH = h - padY * 2;
  const x = (t) => padX + ((t - minT) / (maxT - minT)) * innerW;
  const y = (v) => padY + innerH - (v / maxV) * innerH;
  const pts = points.map((p) => `${x(p.t)},${y(pick(p))}`).join(" ");
  const styles = getComputedStyle(document.documentElement);
  const accent = styles.getPropertyValue("--accent").trim() || "#5e9eff";
  return `<svg viewBox="0 0 ${w} ${h}" width="100%" height="${h}" preserveAspectRatio="none">`
    + `<polyline fill="none" stroke="${accent}" stroke-width="1.5" points="${pts}"/></svg>`;
}
function toggleSeries(k) {
  if (HIDDEN_KEYS.has(k)) HIDDEN_KEYS.delete(k); else HIDDEN_KEYS.add(k);
  if (LAST_DATA) {
    if (CURRENT_TAB === "explore") {
      renderExploreCharts();
      renderExploreTable();
    } else if (CURRENT_TAB === "overview") {
      renderOverviewChart();
    }
  }
}

// ── Live tab ────────────────────────────────────────────────────────
// All events ever received this session, newest-first. We keep these
// even when they're not currently visible so the user can filter to a
// rare process and still see its history (the on-screen table itself is
// capped at LIVE_VISIBLE_LIMIT rows for DOM performance).
const LIVE_BUFFER = [];
const LIVE_BUFFER_CAP = 20000;
const LIVE_VISIBLE_LIMIT = 500;
// Per-process aggregate of every event in the buffer.
// key = `${name}\x00${exe}` -> { name, exe, count, send, recv, last }
const LIVE_AGG = new Map();
let LIVE_FILTER = "";
let LIVE_FILTER_PROC = null;  // pinned process key (set by clicking the summary)
let LIVE_SUMMARY_DIRTY = false;
let LIVE_SUMMARY_TIMER = null;
let LIVE_MATCHED = 0;

function liveMatchesFilter(event) {
  if (LIVE_FILTER_PROC) {
    const key = (event.name || "") + "\x00" + (event.exe || "");
    if (key !== LIVE_FILTER_PROC) return false;
  }
  if (!LIVE_FILTER) return true;
  const q = LIVE_FILTER;
  const fields = [
    event.name, event.exe, event.pname, event.gpname,
    event.domain, event.raddr,
    event.rport != null ? String(event.rport) : "",
  ];
  for (const f of fields) {
    if (f && String(f).toLowerCase().includes(q)) return true;
  }
  return false;
}
function liveAddEventToAggregate(event) {
  const key = (event.name || "") + "\x00" + (event.exe || "");
  let row = LIVE_AGG.get(key);
  if (!row) {
    row = { key, name: event.name || "", exe: event.exe || "", count: 0, send: 0, recv: 0, last: 0 };
    LIVE_AGG.set(key, row);
  }
  row.count += 1;
  row.send += Number(event.send || 0);
  row.recv += Number(event.recv || 0);
  row.last = Date.now() / 1000;
  LIVE_SUMMARY_DIRTY = true;
}
function liveBuildRow(event, ts) {
  // ts: ms since epoch when the event was received
  const tr = document.createElement("tr");
  tr.classList.add("live-row");
  const remote = (event.domain || event.raddr || "") + (event.rport && event.rport > 0 ? ":" + event.rport : "");
  const cells = [
    [new Date(ts).toLocaleTimeString(), false],
    [shortenLabel(event.name, 24), false],
    [shortenLabel(event.pname, 24), false],
    [shortenLabel(event.gpname, 24), false],
    [shortenLabel(remote, 40), false],
    [fmtBytes(event.send || 0), true],
    [fmtBytes(event.recv || 0), true],
  ];
  for (const [val, right] of cells) {
    const td = document.createElement("td");
    if (right) td.className = "right";
    td.textContent = val;
    tr.appendChild(td);
  }
  return tr;
}
function liveUpdateBufferInfo() {
  const el = $("live-buffer-info");
  if (el) el.textContent = `${fmtInt(LIVE_BUFFER.length)} buffered`;
}
function renderLiveSummary() {
  LIVE_SUMMARY_DIRTY = false;
  const tbody = document.querySelector("#live-summary tbody");
  if (!tbody) return;
  const rows = [...LIVE_AGG.values()].sort((a, b) => (b.send + b.recv) - (a.send + a.recv));
  tbody.innerHTML = "";
  for (const r of rows) {
    const tr = document.createElement("tr");
    tr.dataset.key = r.key;
    if (LIVE_FILTER_PROC === r.key) tr.classList.add("active");
    tr.title = (r.exe ? r.exe + "\n" : "") + (r.name || "(none)") + "\nclick to filter to this process";
    tr.addEventListener("click", () => liveToggleProcFilter(r.key));
    const td1 = document.createElement("td");
    td1.textContent = shortenLabel(r.name || r.exe || "(none)", 36);
    const td2 = document.createElement("td"); td2.className = "right"; td2.textContent = fmtInt(r.count);
    const td3 = document.createElement("td"); td3.className = "right"; td3.textContent = fmtBytes(r.send);
    const td4 = document.createElement("td"); td4.className = "right"; td4.textContent = fmtBytes(r.recv);
    tr.appendChild(td1); tr.appendChild(td2); tr.appendChild(td3); tr.appendChild(td4);
    tbody.appendChild(tr);
  }
}
function liveToggleProcFilter(key) {
  LIVE_FILTER_PROC = (LIVE_FILTER_PROC === key) ? null : key;
  liveReapplyFilter();
  renderLiveSummary();
}
function liveReapplyFilter() {
  // Rebuild the visible table from LIVE_BUFFER (newest-first).
  const tbody = document.querySelector("#live-table tbody");
  if (!tbody) return;
  tbody.innerHTML = "";
  let matched = 0;
  for (const entry of LIVE_BUFFER) {
    if (!liveMatchesFilter(entry.event)) continue;
    if (matched >= LIVE_VISIBLE_LIMIT) { matched++; continue; }
    tbody.appendChild(liveBuildRow(entry.event, entry.ts));
    matched++;
  }
  LIVE_MATCHED = matched;
  $("live-stat-matched").textContent = matched;
  $("live-stat-shown").textContent = tbody.childElementCount;
}
function clearLive() {
  LIVE_BUFFER.length = 0;
  LIVE_AGG.clear();
  LIVE_COUNT = 0;
  LIVE_SHOWN = 0;
  LIVE_MATCHED = 0;
  LIVE_RATE.lastT = 0; LIVE_RATE.lastN = 0; LIVE_RATE.smoothed = 0;
  const tbody = document.querySelector("#live-table tbody");
  if (tbody) tbody.innerHTML = "";
  const stbody = document.querySelector("#live-summary tbody");
  if (stbody) stbody.innerHTML = "";
  $("live-count").textContent = 0;
  $("live-stat-count").textContent = 0;
  $("live-stat-shown").textContent = 0;
  $("live-stat-matched").textContent = 0;
  liveUpdateBufferInfo();
}

function setLivePulse(state) {
  // state: "ok" (green), "bad" (red), "idle" (dim green)
  const el = $("live-pulse");
  if (!el) return;
  el.classList.toggle("pulse-bad", state === "bad");
  el.style.opacity = state === "idle" ? "0.3" : "1";
}

function startLive() {
  if (LIVE_ES) return;
  $("live-error").style.display = "none";
  LIVE_ES = new EventSource("/api/live");
  $("live-toggle").textContent = "Stop live feed";
  $("live-status").textContent = "connecting…";
  setLivePulse("bad");  // not green until we actually receive something
  LIVE_ES.addEventListener("error", (ev) => {
    if (ev && ev.data) {
      showLiveError(String(ev.data));
      stopLive(true);
    } else {
      $("live-status").textContent = "disconnected";
      setLivePulse("bad");
    }
  });
  LIVE_ES.onmessage = (ev) => {
    LIVE_COUNT++;
    $("live-count").textContent = LIVE_COUNT;
    $("live-stat-count").textContent = LIVE_COUNT;
    $("live-status").textContent = "connected";
    setLivePulse("ok");
    let event;
    try { event = JSON.parse(ev.data); } catch (_) { return; }
    const ts = Date.now();
    LIVE_BUFFER.unshift({ event, ts });
    if (LIVE_BUFFER.length > LIVE_BUFFER_CAP) LIVE_BUFFER.length = LIVE_BUFFER_CAP;
    liveAddEventToAggregate(event);
    const tbody = document.querySelector("#live-table tbody");
    if (liveMatchesFilter(event)) {
      tbody.insertBefore(liveBuildRow(event, ts), tbody.firstChild);
      while (tbody.childElementCount > LIVE_VISIBLE_LIMIT) tbody.lastElementChild.remove();
      LIVE_MATCHED++;
      $("live-stat-matched").textContent = LIVE_MATCHED;
      $("live-stat-shown").textContent = tbody.childElementCount;
    }
    liveUpdateBufferInfo();
    // sliding event-rate (events/s, ~5s window)
    const now = performance.now();
    if (LIVE_RATE.lastT === 0) {
      LIVE_RATE.lastT = now; LIVE_RATE.lastN = LIVE_COUNT;
    } else if (now - LIVE_RATE.lastT >= 1000) {
      const dt = (now - LIVE_RATE.lastT) / 1000;
      const inst = (LIVE_COUNT - LIVE_RATE.lastN) / dt;
      LIVE_RATE.smoothed = LIVE_RATE.smoothed * 0.6 + inst * 0.4;
      LIVE_RATE.lastT = now; LIVE_RATE.lastN = LIVE_COUNT;
      const r = LIVE_RATE.smoothed.toFixed(LIVE_RATE.smoothed < 10 ? 1 : 0);
      $("status-rate").textContent = r;
      $("meta-rate").textContent = r;
    }
  };
  // Repaint the aggregate at most once per second so high event rates don't pin the UI thread.
  if (LIVE_SUMMARY_TIMER) clearInterval(LIVE_SUMMARY_TIMER);
  LIVE_SUMMARY_TIMER = setInterval(() => {
    if (LIVE_SUMMARY_DIRTY) renderLiveSummary();
  }, 1000);
}
function stopLive(viaError) {
  if (!LIVE_ES) return;
  LIVE_ES.close(); LIVE_ES = null;
  $("live-toggle").textContent = "Start live feed";
  $("live-status").textContent = viaError ? "error" : "stopped";
  setLivePulse(viaError ? "bad" : "idle");
  if (LIVE_SUMMARY_TIMER) { clearInterval(LIVE_SUMMARY_TIMER); LIVE_SUMMARY_TIMER = null; }
}
function showLiveError(msg) {
  const box = $("live-error");
  const lower = msg.toLowerCase();
  let hint = "";
  if (lower.includes("permission") || lower.includes("denied") || lower.includes("eacces")) {
    hint = " Re-run picosnitch webui as root (sudo) so it can read the daemon's runtime state.";
  } else if (lower.includes("no such file") || lower.includes("enoent") || lower.includes("not found")) {
    hint = " The picosnitch daemon may not be running. Start it with `systemctl start picosnitch` or `picosnitch start`.";
  }
  box.textContent = msg + hint;
  box.style.display = "block";
}

// ── auto-refresh + keyboard ─────────────────────────────────────────
function applyAutoRefresh() {
  if (AUTO_REFRESH_TIMER) { clearInterval(AUTO_REFRESH_TIMER); AUTO_REFRESH_TIMER = null; }
  const secs = parseInt($("autorefresh").value, 10);
  if (secs > 0) {
    AUTO_REFRESH_TIMER = setInterval(() => {
      if (CURRENT_TAB === "overview") refreshOverview();
      else if (CURRENT_TAB === "explore") refreshExplore();
    }, secs * 1000);
  }
}

document.addEventListener("keydown", (ev) => {
  if (ev.target && /^(INPUT|SELECT|TEXTAREA)$/.test(ev.target.tagName)) return;
  switch (ev.key) {
    case "1": showTab("overview"); break;
    case "2": showTab("explore"); break;
    case "3": showTab("live"); break;
    case "p":
    case " ":
      if (CURRENT_TAB === "live") {
        ev.preventDefault();
        LIVE_ES ? stopLive() : startLive();
      }
      break;
  }
});

function setMetric(target, metric) {
  if (target === "overview") OVERVIEW_METRIC = metric;
  else EXPLORE_METRIC = metric;
  document.querySelectorAll(`.metric-toggle[data-metric-target="${target}"] button`).forEach((b) => {
    b.classList.toggle("active", b.dataset.metric === metric);
  });
  if (target === "overview") {
    renderOverviewChart();
    renderOverviewLegend();
  } else {
    renderExploreCharts();
    // Re-render drilldown so its sparkline tracks the new metric.
    if (SELECTED_KEY !== null) {
      LAST_DRILLDOWN_KEY = null;  // force a swap; HTML will differ anyway
      loadDrilldown(SELECTED_KEY, { silent: true });
    }
  }
}

// ── boot ────────────────────────────────────────────────────────────
(async function main() {
  applyTheme(document.documentElement.dataset.theme || "dark");
  $("theme-toggle").addEventListener("click", toggleTheme);
  document.querySelectorAll(".metric-toggle button").forEach((btn) => {
    btn.addEventListener("click", () => {
      const target = btn.parentElement.dataset.metricTarget;
      setMetric(target, btn.dataset.metric);
    });
  });
  document.querySelectorAll("#view-tabs .tab").forEach((el) => {
    el.addEventListener("click", () => showTab(el.dataset.tab));
  });
  await loadMeta();
  $("where").addEventListener("change", loadWhereOptions);
  $("whereis").addEventListener("change", refreshExplore);
  $("refresh").addEventListener("click", refreshExplore);
  $("autorefresh").addEventListener("change", applyAutoRefresh);
  $("live-toggle").addEventListener("click", () => { LIVE_ES ? stopLive() : startLive(); });
  const clearBtn = $("live-clear");
  if (clearBtn) clearBtn.addEventListener("click", clearLive);
  const filterEl = $("live-filter");
  if (filterEl) {
    filterEl.addEventListener("input", () => {
      LIVE_FILTER = filterEl.value.trim().toLowerCase();
      liveReapplyFilter();
    });
  }

  showTab("overview");
  applyAutoRefresh();
  if (SUMMARY_TIMER) clearInterval(SUMMARY_TIMER);
  SUMMARY_TIMER = setInterval(refreshSummary, 30000);
  if (META_REFRESH_TIMER) clearInterval(META_REFRESH_TIMER);
  META_REFRESH_TIMER = setInterval(refreshMeta, 30000);
  if (UPTIME_TIMER) clearInterval(UPTIME_TIMER);
  UPTIME_TIMER = setInterval(updateUptimeLabel, 1000);
})();
