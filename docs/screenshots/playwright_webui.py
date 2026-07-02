#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta
"""
Capture picosnitch web UI screenshots and a narrated WebM recording
using headless chromium via Playwright.

Two passes:
  1. capture_stills() -- fast unrecorded pass that captures every PNG
     state, including the light-mode variant.
  2. capture_video()  -- slower narrated pass, dark mode only, with a
     virtual cursor + click ripple + bottom-of-screen key/action toast
     injected into the page so the recording is self-explanatory.

Assumes the seeded DB exists (see seed_db.py) and PICOSNITCH_TEST=1 is
set so DATA_DIR resolves under /tmp/picosnitch. Launches the webui on
127.0.0.1 with a deterministic port, captures everything, then shuts
the server down.
"""

import asyncio
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

os.environ.setdefault("PICOSNITCH_TEST", "1")

HERE = Path(__file__).resolve().parent
OUT_DIR = HERE / "out"
PORT = int(os.getenv("PICOSNITCH_SCREENSHOT_PORT", "5191"))
HOST = "127.0.0.1"
BASE_URL = f"http://{HOST}:{PORT}"
VIEWPORT = {"width": 1600, "height": 1000}
DEVICE_SCALE_FACTOR = 2


# ── injected page overlay ─────────────────────────────────────────────
# Adds a virtual cursor (since headless chromium recordings include no
# OS pointer), a click ripple animation, and a bottom-center toast for
# narrating actions / key presses. Self-installing once per document via
# add_init_script so it survives navigations and reloads.
OVERLAY_INIT_SCRIPT = r"""
(() => {
  if (window.__pwOverlayInit) return;
  window.__pwOverlayInit = true;
  const install = () => {
    if (!document.body || document.getElementById('__pw_cursor')) return;
    const cursor = document.createElement('div');
    cursor.id = '__pw_cursor';
    cursor.style.cssText = (
      'position:fixed;left:50%;top:50%;width:22px;height:22px;'
      + 'border-radius:50%;background:rgba(255,255,255,0.94);'
      + 'border:2px solid #1a1b26;pointer-events:none;z-index:2147483646;'
      + 'transform:translate(-50%,-50%);box-shadow:0 0 10px rgba(0,0,0,0.55);'
      + 'transition:left 650ms cubic-bezier(.25,.46,.45,.94),'
      + 'top 650ms cubic-bezier(.25,.46,.45,.94);'
    );
    document.documentElement.appendChild(cursor);
    const toast = document.createElement('div');
    toast.id = '__pw_toast';
    toast.style.cssText = (
      'position:fixed;bottom:36px;left:50%;'
      + 'transform:translateX(-50%) translateY(24px);'
      + 'background:rgba(18,20,38,0.94);color:#f7f9ff;'
      + 'padding:12px 22px;border-radius:10px;'
      + 'font:600 16px ui-monospace,SFMono-Regular,Menlo,monospace;'
      + 'letter-spacing:0.04em;z-index:2147483647;opacity:0;'
      + 'pointer-events:none;transition:opacity 220ms ease,'
      + 'transform 220ms ease;border:1px solid rgba(122,162,247,0.55);'
      + 'box-shadow:0 10px 28px rgba(0,0,0,0.5);'
    );
    document.documentElement.appendChild(toast);
    const sty = document.createElement('style');
    sty.textContent = (
      '@keyframes __pwRipple { '
      + '0% { width:22px; height:22px; opacity:0.85; border-width:2px; } '
      + '100% { width:90px; height:90px; opacity:0; border-width:1px; } }'
    );
    document.head.appendChild(sty);
    window.__pwMoveCursor = (x, y) => {
      cursor.style.left = x + 'px';
      cursor.style.top = y + 'px';
    };
    window.__pwClickRipple = () => {
      const r = document.createElement('div');
      r.style.cssText = (
        'position:fixed;left:' + (cursor.style.left || '50%')
        + ';top:' + (cursor.style.top || '50%')
        + ';border-radius:50%;border:2px solid #7aa2f7;'
        + 'pointer-events:none;z-index:2147483645;'
        + 'transform:translate(-50%,-50%);'
        + 'animation:__pwRipple 0.7s ease-out forwards;'
      );
      document.documentElement.appendChild(r);
      setTimeout(() => r.remove(), 750);
    };
    let toastTimer;
    window.__pwToast = (msg, ms) => {
      toast.textContent = msg;
      toast.style.opacity = '1';
      toast.style.transform = 'translateX(-50%) translateY(0)';
      clearTimeout(toastTimer);
      toastTimer = setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(-50%) translateY(24px)';
      }, ms || 1700);
    };
  };
  if (document.body) install();
  else document.addEventListener('DOMContentLoaded', install);
})();
"""


# ── helpers ───────────────────────────────────────────────────────────


def _pick_python() -> str:
    venv = HERE.parent.parent / ".venv" / "bin" / "python"
    return str(venv) if venv.exists() else sys.executable


def _wait_port(host: str, port: int, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


class Overlay:
    """Wraps playwright actions with virtual cursor + toast + ripple."""

    def __init__(self, page) -> None:
        self.page = page

    async def toast(self, msg: str, ms: int = 1800, after: int = 450) -> None:
        await self.page.evaluate(f"window.__pwToast({json.dumps(msg)}, {ms})")
        if after:
            await self.page.wait_for_timeout(after)

    async def move_to(self, selector: str, settle: int = 720) -> None:
        bbox = await self.page.locator(selector).bounding_box()
        if not bbox:
            return
        cx = bbox["x"] + bbox["width"] / 2
        cy = bbox["y"] + bbox["height"] / 2
        await self.page.evaluate(f"window.__pwMoveCursor({cx}, {cy})")
        await self.page.wait_for_timeout(settle)

    async def click(self, selector: str, label: str | None = None, settle: int = 700) -> None:
        await self.move_to(selector)
        if label:
            await self.toast(label, after=320)
        await self.page.evaluate("window.__pwClickRipple()")
        await self.page.wait_for_timeout(180)
        await self.page.click(selector)
        await self.page.wait_for_timeout(settle)

    async def select(self, selector: str, value: str, label: str | None = None, settle: int = 700) -> None:
        await self.move_to(selector)
        if label:
            await self.toast(label, after=320)
        await self.page.select_option(selector, value)
        await self.page.wait_for_timeout(settle)

    async def hover_chart(self, selector: str, label: str | None = None, steps: int = 7) -> None:
        """Sweep a real mouse across a chart's <svg> so its hover tooltip
        tracks the cursor. The visual overlay cursor only moves a div, so we
        also dispatch actual mouse moves that fire the chart's mousemove."""
        box = await self.page.locator(f"{selector} svg").bounding_box()
        if not box:
            return
        if label:
            await self.toast(label, after=260)
        y = box["y"] + box["height"] * 0.45
        x0, x1 = box["x"] + box["width"] * 0.16, box["x"] + box["width"] * 0.9
        for i in range(steps + 1):
            x = x0 + (x1 - x0) * i / steps
            await self.page.mouse.move(x, y)
            await self.page.evaluate(f"window.__pwMoveCursor({x}, {y})")
            await self.page.wait_for_timeout(130)
        await self.page.wait_for_timeout(320)


# ── shared building blocks ────────────────────────────────────────────


async def _select_view(page, view: str) -> None:
    await page.click(f'#view-tabs li.tab[data-tab="{view}"]')
    await page.wait_for_selector(f"#tab-{view}.active")


async def _select_group(page, dim: str) -> None:
    await page.click(f'#group-by li[data-dim="{dim}"]')


async def _select_range(page, preset: str) -> None:
    pop = page.locator("#range-pop")
    await pop.evaluate("el => el.setAttribute('open', '')")
    await page.click(f'#range-presets button[data-preset="{preset}"]')
    await page.wait_for_function(
        "preset => document.querySelector('#range-summary').textContent.includes(preset)",
        arg=preset,
    )
    await page.wait_for_load_state("networkidle")


# ── pass 1: stills ────────────────────────────────────────────────────


async def capture_stills(pw, out_dir: Path) -> None:
    browser = await pw.chromium.launch(headless=True)
    context = await browser.new_context(
        viewport=VIEWPORT,
        device_scale_factor=DEVICE_SCALE_FACTOR,
        color_scheme="dark",
    )
    page = await context.new_page()

    async def shot(name: str) -> None:
        path = out_dir / f"webui-{name}.png"
        await page.screenshot(path=str(path), full_page=False)
        print(f"  wrote {path.name}")

    # 1. Default landing -- Overview tab on 1h range
    await page.goto(f"{BASE_URL}/", wait_until="networkidle")
    await page.wait_for_selector("#tab-overview.active")
    await page.wait_for_selector("#overview-table tbody tr")
    await shot("overview-1h")

    # 2. Overview at 1d range -- richer chart for the README hero
    await _select_range(page, "1d")
    await page.wait_for_timeout(400)
    await shot("overview-1d")

    # 3. Light theme variant of the same overview
    await page.evaluate("window.localStorage.setItem('picosnitch-theme', 'light')")
    await page.reload(wait_until="networkidle")
    await page.wait_for_selector("#overview-table tbody tr")
    await _select_range(page, "1d")
    await page.wait_for_timeout(400)
    await shot("overview-1d-light")
    # Restore dark theme for the remaining shots
    await page.evaluate("window.localStorage.setItem('picosnitch-theme', 'dark')")
    await page.reload(wait_until="networkidle")
    await page.wait_for_selector("#tab-overview.active")

    # 4. Explore tab grouped by executable. The per-executable view is
    # picosnitch's whole point, so this is the README/docs hero shot.
    await _select_view(page, "explore")
    await page.wait_for_selector("#group-by li[data-dim]")
    await _select_group(page, "exe")
    await _select_range(page, "1d")
    await page.wait_for_selector("#totals tbody tr")
    await page.click("#totals tbody tr:first-child")
    await page.wait_for_selector("#drilldown-pane .meta-cell")
    await page.wait_for_load_state("networkidle")
    await page.wait_for_timeout(400)
    await shot("by-exe-1d")

    # 5. Explore tab grouped by domain. Click the top row so the
    # right-hand drilldown pane is populated for the screenshot.
    await _select_group(page, "domain")
    await page.wait_for_selector("#totals tbody tr")
    await page.click("#totals tbody tr:first-child")
    await page.wait_for_selector("#drilldown-pane .meta-cell")
    await page.wait_for_load_state("networkidle")
    await page.wait_for_timeout(400)
    await shot("by-domain-1d")

    # 6. Filter to a single process name (firefox "Web Content") at 1d.
    # Group by name then click the matching row so the drilldown panel
    # is populated for this state too.
    await _select_group(page, "name")
    await page.select_option("#where", "name")
    await page.wait_for_function("document.querySelector('#whereis').options.length > 1")
    await page.select_option("#whereis", "Web Content")
    await page.wait_for_load_state("networkidle")
    await page.wait_for_selector("#totals tbody tr")
    await page.click("#totals tbody tr:first-child")
    await page.wait_for_selector("#drilldown-pane .meta-cell")
    await page.wait_for_load_state("networkidle")
    await page.wait_for_timeout(400)
    await shot("filter-web-content")

    # 7. Live tab -- reset filter first so explore stays clean
    await page.select_option("#where", "")
    await _select_view(page, "live")
    await page.wait_for_selector("#live-toggle")
    await page.click("#live-toggle")
    await page.wait_for_timeout(4000)
    await shot("live")

    await context.close()
    await browser.close()


# ── pass 2: narrated video ────────────────────────────────────────────


async def capture_video(pw, out_dir: Path) -> None:
    video_dir = out_dir / "_pw_video"
    if video_dir.exists():
        shutil.rmtree(video_dir)
    video_dir.mkdir()

    browser = await pw.chromium.launch(headless=True)
    context = await browser.new_context(
        viewport=VIEWPORT,
        device_scale_factor=DEVICE_SCALE_FACTOR,
        color_scheme="dark",
        record_video_dir=str(video_dir),
        record_video_size=VIEWPORT,
    )
    await context.add_init_script(OVERLAY_INIT_SCRIPT)
    page = await context.new_page()
    o = Overlay(page)

    # Land on the overview tab and let the chart settle.
    await page.goto(f"{BASE_URL}/", wait_until="networkidle")
    await page.wait_for_selector("#tab-overview.active")
    await page.wait_for_selector("#overview-table tbody tr")
    await page.wait_for_timeout(900)
    await o.toast("Overview · last hour", ms=1800, after=900)

    # Stretch the time range out to a day so the chart fills in.
    pop = page.locator("#range-pop")
    await o.move_to("#range-summary", settle=450)
    await pop.evaluate("el => el.setAttribute('open', '')")
    await page.wait_for_timeout(300)
    await o.click('#range-presets button[data-preset="1d"]', label="Range → 1 day", settle=500)
    await page.wait_for_load_state("networkidle")
    await page.wait_for_timeout(900)

    # Play with the chart: hover it for the docked tooltip, then swap the
    # metric between received / sent / total and watch it re-stack.
    await o.hover_chart("#overview-chart", label="Hover the chart for details")
    await o.click('.metric-toggle[data-metric-target="overview"] button[data-metric="s"]', label="Metric → Sent", settle=550)
    await o.click('.metric-toggle[data-metric-target="overview"] button[data-metric="t"]', label="Metric → Total", settle=550)
    await o.hover_chart("#overview-chart")
    await o.click('.metric-toggle[data-metric-target="overview"] button[data-metric="r"]', label="Metric → Received", settle=450)

    # Switch to the explore tab.
    await o.click('#view-tabs li.tab[data-tab="explore"]', label="Tab → Explore", settle=500)
    await page.wait_for_selector("#tab-explore.active")
    await page.wait_for_selector("#group-by li[data-dim]")
    await page.wait_for_timeout(500)

    # Group by domain, then drill into the top contributor.
    await o.click('#group-by li[data-dim="domain"]', label="Group by → Domain", settle=550)
    await page.wait_for_selector("#totals tbody tr")
    await page.wait_for_timeout(500)
    await o.click("#totals tbody tr:first-child", label="Drill down on top domain", settle=600)
    await page.wait_for_selector("#drilldown-pane .meta-cell")
    await page.wait_for_timeout(700)

    # Interact with the explore chart too: total metric + hover.
    await o.click('.metric-toggle[data-metric-target="explore"] button[data-metric="t"]', label="Metric → Total", settle=500)
    await o.hover_chart("#chart-main", label="Hover for per-series totals")

    # Now group by process name and filter to firefox "Web Content".
    await o.click('#group-by li[data-dim="name"]', label="Group by → Name", settle=500)
    await page.wait_for_selector("#totals tbody tr")
    await page.wait_for_timeout(500)
    await o.select("#where", "name", label="Filter where → name", settle=500)
    await page.wait_for_function("document.querySelector('#whereis').options.length > 1")
    await o.select("#whereis", "Web Content", label='Filter is → "Web Content"', settle=550)
    await page.wait_for_load_state("networkidle")
    await page.wait_for_selector("#totals tbody tr")
    await page.wait_for_timeout(500)
    await o.click("#totals tbody tr:first-child", label="Drill down on Web Content", settle=600)
    await page.wait_for_selector("#drilldown-pane .meta-cell")
    await page.wait_for_timeout(1400)

    # Reset filter and head to the live feed.
    await o.select("#where", "", label="Clear filter", settle=500)
    await o.click('#view-tabs li.tab[data-tab="live"]', label="Tab → Live", settle=500)
    await page.wait_for_selector("#live-toggle")
    await page.wait_for_timeout(500)
    await o.click("#live-toggle", label="Start live stream", settle=500)
    await page.wait_for_timeout(4200)
    await o.toast("Live events streaming…", ms=2000, after=1600)

    await context.close()
    await browser.close()

    # Move the playwright-generated webm into a stable name.
    videos = sorted(video_dir.glob("*.webm"))
    if videos:
        target = out_dir / "web_ui.webm"
        if target.exists():
            target.unlink()
        videos[-1].rename(target)
        print(f"  wrote {target.name}")
    shutil.rmtree(video_dir, ignore_errors=True)


# ── orchestration ─────────────────────────────────────────────────────


async def capture(out_dir: Path) -> int:
    from playwright.async_api import async_playwright

    out_dir.mkdir(parents=True, exist_ok=True)
    async with async_playwright() as pw:
        await capture_stills(pw, out_dir)
        await capture_video(pw, out_dir)
    return 0


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    py = _pick_python()
    env = {**os.environ, "PICOSNITCH_TEST": "1", "PICOSNITCH_HOST": HOST, "PICOSNITCH_PORT": str(PORT)}
    proc = subprocess.Popen([py, "-m", "picosnitch", "webui"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        if not _wait_port(HOST, PORT, timeout=15.0):
            err = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
            print(f"webui failed to bind {HOST}:{PORT}\n{err}", file=sys.stderr)
            return 1
        return asyncio.run(capture(OUT_DIR))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


if __name__ == "__main__":
    sys.exit(main())
