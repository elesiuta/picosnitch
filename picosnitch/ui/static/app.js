// SPDX-License-Identifier: GPL-3.0-or-later
"use strict";

const $ = (id) => document.getElementById(id);

const PALETTE = ["#5e9eff", "#ff7a59", "#5fd1a0", "#f4c869", "#c98ad7", "#7fcde1", "#e26a6a", "#9bbf5e", "#d49ad6", "#7fc6c6", "#e9a06a", "#88a4d2", "#9d6f9c", "#5cb085", "#cc8a8a", "#7d97c2", "#a4cf85", "#bf8a5c", "#7c8d9e", "#aab7c4"];

let META = null;
let LIVE_ES = null;
let LIVE_COUNT = 0;
let LAST_DATA = null;
const HIDDEN_KEYS = new Set();

function fmtBytes(n) {
  if (!n) return "0";
  const u = ["B", "K", "M", "G", "T"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return n.toFixed(n < 10 && i > 0 ? 1 : 0) + u[i];
}

function fmtTimeShort(ts) {
  const d = new Date(ts * 1000);
  return d.toLocaleString();
}

function shortenLabel(s, max) {
  if (!s) return "(none)";
  if (s.length <= max) return s;
  return s.slice(0, max / 2 | 0) + "…" + s.slice(-(max / 2 | 0));
}

async function loadMeta() {
  const r = await fetch("/api/meta");
  META = await r.json();
  $("version").textContent = "v" + META.version;
  $("status").textContent = META.status + "  ·  " + META.db;
  $("footer").textContent = "picosnitch " + META.version;
  const dimSel = $("dim");
  const whereSel = $("where");
  for (const [k, label] of Object.entries(META.dims)) {
    const opt = document.createElement("option");
    opt.value = k; opt.textContent = label; dimSel.appendChild(opt);
    const opt2 = opt.cloneNode(true); whereSel.appendChild(opt2);
  }
  const rangeSel = $("range");
  for (const r of META.ranges) {
    const opt = document.createElement("option");
    opt.value = r; opt.textContent = r; rangeSel.appendChild(opt);
  }
  rangeSel.value = "1h";
}

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

function renderChart(targetId, data, kind) {
  // kind: "s" (sent) or "r" (received). Renders one stacked-area-like SVG with per-series lines.
  const target = $(targetId);
  target.innerHTML = "";
  const series = data.series;
  const keys = Object.keys(series);
  if (keys.length === 0) {
    target.innerHTML = '<div class="muted" style="padding:20px;">no data</div>';
    return;
  }
  // collect all timestamps and find global x range and per-series max.
  // Hidden series still contribute to the x range (so toggling doesn't shift
  // the time axis) but are excluded from the y-axis max so the visible
  // series can scale up to fill the chart.
  let minT = Infinity, maxT = -Infinity, maxY = 0;
  for (const k of keys) {
    const arr = series[k];
    const visible = !HIDDEN_KEYS.has(k);
    for (let i = 0; i < arr.t.length; i++) {
      if (arr.t[i] < minT) minT = arr.t[i];
      if (arr.t[i] > maxT) maxT = arr.t[i];
      if (visible && arr[kind][i] > maxY) maxY = arr[kind][i];
    }
  }
  if (maxT === minT) maxT = minT + data.bucket;
  if (maxY === 0) maxY = 1;
  const W = target.clientWidth || 800;
  const H = 220;
  const padL = 50, padR = 10, padT = 10, padB = 22;
  const innerW = W - padL - padR, innerH = H - padT - padB;
  const x = (t) => padL + ((t - minT) / (maxT - minT)) * innerW;
  const y = (v) => padT + innerH - (v / maxY) * innerH;

  // wrap target so we can absolutely-position the tooltip overlay relative to it
  target.style.position = "relative";

  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.setAttribute("preserveAspectRatio", "none");
  svg.setAttribute("height", H);
  svg.setAttribute("width", "100%");
  // gridlines
  // gridlines
  const grid = document.createElementNS("http://www.w3.org/2000/svg", "g");
  grid.setAttribute("stroke", "#2a313c"); grid.setAttribute("stroke-width", "1");
  for (let i = 0; i <= 4; i++) {
    const yy = padT + (innerH * i / 4);
    const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
    line.setAttribute("x1", padL); line.setAttribute("x2", W - padR);
    line.setAttribute("y1", yy); line.setAttribute("y2", yy);
    grid.appendChild(line);
    const lbl = document.createElementNS("http://www.w3.org/2000/svg", "text");
    lbl.setAttribute("x", padL - 4); lbl.setAttribute("y", yy + 4);
    lbl.setAttribute("fill", "#889099"); lbl.setAttribute("font-size", "10");
    lbl.setAttribute("text-anchor", "end");
    lbl.textContent = fmtBytes(maxY * (1 - i / 4));
    grid.appendChild(lbl);
  }
  svg.appendChild(grid);
  // x-axis labels
  const xlbl1 = document.createElementNS("http://www.w3.org/2000/svg", "text");
  xlbl1.setAttribute("x", padL); xlbl1.setAttribute("y", H - 4);
  xlbl1.setAttribute("fill", "#889099"); xlbl1.setAttribute("font-size", "10");
  xlbl1.textContent = fmtTimeShort(minT);
  svg.appendChild(xlbl1);
  const xlbl2 = document.createElementNS("http://www.w3.org/2000/svg", "text");
  xlbl2.setAttribute("x", W - padR); xlbl2.setAttribute("y", H - 4);
  xlbl2.setAttribute("fill", "#889099"); xlbl2.setAttribute("font-size", "10");
  xlbl2.setAttribute("text-anchor", "end");
  xlbl2.textContent = fmtTimeShort(maxT);
  svg.appendChild(xlbl2);
  // series lines
  const seriesPoints = []; // [{key, color, pts:[{t,v,xPx,yPx}]}]
  keys.forEach((k, i) => {
    const arr = series[k];
    const color = PALETTE[i % PALETTE.length];
    const pts = [];
    const recorded = [];
    for (let j = 0; j < arr.t.length; j++) {
      const xPx = x(arr.t[j]);
      const yPx = y(arr[kind][j]);
      pts.push(xPx + "," + yPx);
      recorded.push({ t: arr.t[j], v: arr[kind][j], xPx, yPx });
    }
    if (pts.length === 0) return;
    const poly = document.createElementNS("http://www.w3.org/2000/svg", "polyline");
    poly.setAttribute("fill", "none");
    poly.setAttribute("stroke", color);
    poly.setAttribute("stroke-width", "1.5");
    poly.setAttribute("points", pts.join(" "));
    poly.dataset.key = k;
    if (HIDDEN_KEYS.has(k)) poly.classList.add("hidden");
    svg.appendChild(poly);
    seriesPoints.push({ key: k, color, pts: recorded });
  });
  // hover overlay: vertical guide + tooltip
  const guide = document.createElementNS("http://www.w3.org/2000/svg", "line");
  guide.setAttribute("stroke", "#888"); guide.setAttribute("stroke-width", "0.5");
  guide.setAttribute("stroke-dasharray", "2,2"); guide.setAttribute("y1", padT); guide.setAttribute("y2", padT + innerH);
  guide.setAttribute("x1", -10); guide.setAttribute("x2", -10);
  svg.appendChild(guide);
  const dots = [];
  for (const _ of seriesPoints) {
    const c = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    c.setAttribute("r", "3"); c.setAttribute("fill", "transparent");
    svg.appendChild(c); dots.push(c);
  }
  target.appendChild(svg);
  const tip = document.createElement("div");
  tip.className = "chart-tooltip";
  tip.style.display = "none";
  target.appendChild(tip);
  svg.addEventListener("mousemove", (ev) => {
    const rect = svg.getBoundingClientRect();
    // viewBox -> client px scale: SVG preserveAspectRatio=none stretches
    const scaleX = rect.width / W;
    const scaleY = rect.height / H;
    const mxView = (ev.clientX - rect.left) / scaleX;
    if (mxView < padL || mxView > W - padR) { tip.style.display = "none"; guide.setAttribute("x1", -10); guide.setAttribute("x2", -10); dots.forEach(d => d.setAttribute("fill", "transparent")); return; }
    // map mxView back to time
    const tHover = minT + ((mxView - padL) / innerW) * (maxT - minT);
    // for each series find nearest point
    const lines = [];
    let snapX = mxView;
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
        if (idx === 0) snapX = best.xPx;
        lines.push(`<div><span class="legend-swatch" style="background:${sp.color}"></span>${escapeHtml(shortenLabel(sp.key || "(none)", 60))}: <strong>${fmtBytes(best.v)}</strong></div>`);
      }
    });
    guide.setAttribute("x1", snapX); guide.setAttribute("x2", snapX);
    const ts = seriesPoints.length && seriesPoints[0].pts.length ? seriesPoints[0].pts.reduce((a, b) => Math.abs(a.t - tHover) < Math.abs(b.t - tHover) ? a : b).t : tHover;
    tip.innerHTML = `<div class="muted">${fmtTimeShort(ts)}</div>${lines.join("")}`;
    tip.style.display = "block";
    // position tooltip at mouse, clamped to chart bounds
    const tipX = ev.clientX - rect.left + 12;
    const tipY = ev.clientY - rect.top + 12;
    tip.style.left = Math.min(rect.width - 220, Math.max(0, tipX)) + "px";
    tip.style.top = Math.min(rect.height - 80, Math.max(0, tipY)) + "px";
  });
  svg.addEventListener("mouseleave", () => {
    tip.style.display = "none";
    guide.setAttribute("x1", -10); guide.setAttribute("x2", -10);
    dots.forEach(d => d.setAttribute("fill", "transparent"));
  });
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function toggleSeries(k) {
  if (HIDDEN_KEYS.has(k)) HIDDEN_KEYS.delete(k); else HIDDEN_KEYS.add(k);
  if (LAST_DATA) {
    renderChart("chart-send", LAST_DATA, "s");
    renderChart("chart-recv", LAST_DATA, "r");
    renderTotals(LAST_DATA);
  }
}

function renderTotals(data) {
  $("totals-head").textContent = data.label;
  const tbody = document.querySelector("#totals tbody");
  tbody.innerHTML = "";
  const keys = Object.keys(data.totals);
  keys.forEach((k, i) => {
    const tr = document.createElement("tr");
    tr.title = (k || "(none)") + "\nSent: " + fmtBytes(data.totals[k].send) + "\nRecv: " + fmtBytes(data.totals[k].recv) + "\n(click to show/hide)";
    tr.dataset.key = k;
    tr.classList.add("legend-row");
    if (HIDDEN_KEYS.has(k)) tr.classList.add("hidden");
    tr.addEventListener("click", () => toggleSeries(k));
    const color = PALETTE[i % PALETTE.length];
    const td1 = document.createElement("td");
    const swatch = document.createElement("span");
    swatch.className = "legend-swatch";
    swatch.style.background = color;
    td1.appendChild(swatch);
    td1.appendChild(document.createTextNode(shortenLabel(k || "(none)", 100)));
    const td2 = document.createElement("td"); td2.className = "right"; td2.textContent = fmtBytes(data.totals[k].send);
    const td3 = document.createElement("td"); td3.className = "right"; td3.textContent = fmtBytes(data.totals[k].recv);
    tr.appendChild(td1); tr.appendChild(td2); tr.appendChild(td3);
    tbody.appendChild(tr);
  });
}

async function refresh() {
  const dim = $("dim").value;
  const range = $("range").value;
  const where = $("where").value;
  const whereis = $("whereis").value;
  const limit = $("limit").value;
  let url = `/api/aggregate?dim=${encodeURIComponent(dim)}&range=${encodeURIComponent(range)}&limit=${encodeURIComponent(limit)}`;
  if (where && whereis) url += `&where=${encodeURIComponent(where)}&whereis=${encodeURIComponent(whereis)}`;
  const r = await fetch(url);
  const data = await r.json();
  LAST_DATA = data;
  renderChart("chart-send", data, "s");
  renderChart("chart-recv", data, "r");
  renderTotals(data);
}

function setupTabs() {
  document.querySelectorAll(".tab").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
      btn.classList.add("active");
      $("tab-" + btn.dataset.tab).classList.add("active");
    });
  });
}

function startLive() {
  if (LIVE_ES) return;
  $("live-error").style.display = "none";
  LIVE_ES = new EventSource("/api/live");
  $("live-toggle").textContent = "Stop live feed";
  $("live-status").textContent = "connected";
  LIVE_ES.addEventListener("error", (ev) => {
    // Named SSE "error" events from the server carry a data payload
    // describing why the live feed is unavailable (e.g. permission denied).
    // The generic connection-error event has no data field.
    if (ev && ev.data) {
      showLiveError(String(ev.data));
      stopLive();
    } else {
      $("live-status").textContent = "disconnected";
    }
  });
  LIVE_ES.onmessage = (ev) => {
    LIVE_COUNT++;
    $("live-count").textContent = LIVE_COUNT;
    let event;
    try { event = JSON.parse(ev.data); } catch { return; }
    const tbody = document.querySelector("#live-table tbody");
    const tr = document.createElement("tr");
    const remote = (event.domain || event.raddr || "") + (event.rport && event.rport > 0 ? ":" + event.rport : "");
    const cells = [
      new Date().toLocaleTimeString(),
      shortenLabel(event.name || "", 24),
      shortenLabel(event.pname || "", 24),
      shortenLabel(event.gpname || "", 24),
      shortenLabel(remote, 40),
      fmtBytes(event.send || 0),
      fmtBytes(event.recv || 0),
    ];
    cells.forEach((val, idx) => {
      const td = document.createElement("td");
      if (idx >= 5) td.className = "right";
      td.textContent = val;
      tr.appendChild(td);
    });
    tbody.insertBefore(tr, tbody.firstChild);
    while (tbody.childElementCount > 500) tbody.lastElementChild.remove();
  };
}

function stopLive() {
  if (!LIVE_ES) return;
  LIVE_ES.close(); LIVE_ES = null;
  $("live-toggle").textContent = "Start live feed";
  $("live-status").textContent = "stopped";
}

function showLiveError(msg) {
  const box = $("live-error");
  const lower = msg.toLowerCase();
  let hint = "";
  if (lower.includes("permission") || lower.includes("denied") || lower.includes("eacces")) {
    hint = " Re-run picosnitch webui as root (sudo), or add your user to the picosnitch group.";
  } else if (lower.includes("no such file") || lower.includes("enoent") || lower.includes("not found")) {
    hint = " The picosnitch daemon may not be running. Start it with `systemctl start picosnitch` or `picosnitch start`.";
  }
  box.textContent = msg + hint;
  box.style.display = "block";
}

function setupLive() {
  $("live-toggle").addEventListener("click", () => { LIVE_ES ? stopLive() : startLive(); });
}

let AUTO_REFRESH_TIMER = null;
function setupAutoRefresh() {
  const sel = $("autorefresh");
  function apply() {
    if (AUTO_REFRESH_TIMER) { clearInterval(AUTO_REFRESH_TIMER); AUTO_REFRESH_TIMER = null; }
    const secs = parseInt(sel.value, 10);
    if (secs > 0) {
      AUTO_REFRESH_TIMER = setInterval(refresh, secs * 1000);
    }
  }
  sel.addEventListener("change", apply);
  apply();
}

(async function main() {
  setupTabs();
  setupLive();
  await loadMeta();
  $("where").addEventListener("change", loadWhereOptions);
  $("refresh").addEventListener("click", refresh);
  $("dim").addEventListener("change", refresh);
  $("range").addEventListener("change", refresh);
  $("whereis").addEventListener("change", refresh);
  $("limit").addEventListener("change", refresh);
  setupAutoRefresh();
  refresh();
})();

// Escape any text content insertion that uses innerHTML by manually clearing first.
// (We control all values; for safety, shortenLabel output is clamped and attribute interpolations use only fmtBytes/Date which produce safe primitives.)
