#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta
"""
Orchestrate offline picosnitch screenshot/video generation.

Pipeline:
    1. seed_db.py        -- write a deterministic test database
    2. playwright_webui  -- capture webui PNGs + WebM
    3. mock_feed.py + VHS tui.tape  -- capture TUI PNGs + WebM
    4. mock_feed.py + VHS top.tape  -- capture top PNGs + WebM
    5. VHS demo.tape     -- short hero WebM for the README

All output lands in docs/screenshots/out/. The `pages` workflow runs this
on every release and then builds the MkDocs site, which bundles
docs/screenshots/out/ into the published site -- so the media ships with
the docs and the README/docs reference it there (no GitHub Release assets).
--publish additionally copies a curated subset onto docs/ for legacy hero
assets; it is not used by CI.
"""

import argparse
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
OUT_DIR = HERE / "out"

os.environ.setdefault("PICOSNITCH_TEST", "1")

# Filesize budgets (bytes).
PNG_BUDGET = 1500 * 1024
WEBM_BUDGET = 8 * 1024 * 1024


# ---------------------------------------------------------------- helpers


def _run(cmd: list[str], **kwargs) -> int:
    print(f"\n$ {' '.join(cmd)}")
    return subprocess.run(cmd, **kwargs).returncode


def _which(name: str) -> str | None:
    return shutil.which(name)


def _check_tool(name: str, install_hint: str) -> str:
    path = _which(name)
    if not path:
        print(f"ERROR: missing tool '{name}'. Install with: {install_hint}", file=sys.stderr)
        sys.exit(2)
    return path


def _start_mock_feed() -> subprocess.Popen:
    py = sys.executable
    proc = subprocess.Popen(
        [py, str(HERE / "mock_feed.py")],
        env={**os.environ, "PICOSNITCH_TEST": "1"},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    # Wait for socket
    sock_path = Path("/tmp/picosnitch/run/picosnitch/events.sock")
    deadline = time.time() + 5
    while time.time() < deadline:
        if sock_path.exists():
            return proc
        time.sleep(0.05)
    proc.terminate()
    raise RuntimeError("mock_feed.py did not create the events socket within 5s")


def _stop_mock_feed(proc: subprocess.Popen) -> None:
    proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


# ---------------------------------------------------------------- stages


def stage_seed() -> None:
    rc = _run([sys.executable, str(HERE / "seed_db.py")])
    if rc != 0:
        sys.exit(rc)


def stage_webui() -> None:
    feed = _start_mock_feed()
    try:
        rc = _run([sys.executable, str(HERE / "playwright_webui.py")])
    finally:
        _stop_mock_feed(feed)
    if rc != 0:
        sys.exit(rc)


def stage_tui(vhs: str) -> None:
    feed = _start_mock_feed()
    try:
        rc = _run([vhs, str(HERE / "vhs" / "tui.tape")], cwd=str(REPO_ROOT))
    finally:
        _stop_mock_feed(feed)
    if rc != 0:
        sys.exit(rc)


def stage_top(vhs: str) -> None:
    feed = _start_mock_feed()
    try:
        rc = _run([vhs, str(HERE / "vhs" / "top.tape")], cwd=str(REPO_ROOT))
    finally:
        _stop_mock_feed(feed)
    if rc != 0:
        sys.exit(rc)


def stage_demo(vhs: str) -> None:
    feed = _start_mock_feed()
    try:
        rc = _run([vhs, str(HERE / "vhs" / "demo.tape")], cwd=str(REPO_ROOT))
    finally:
        _stop_mock_feed(feed)
    if rc != 0:
        sys.exit(rc)


def stage_keystrokes() -> None:
    """Burn stacked keystroke toasts into each VHS-recorded webm."""
    sys.path.insert(0, str(HERE))
    try:
        from keystroke_overlay import overlay  # noqa: PLC0415
    finally:
        sys.path.pop(0)
    pairs = [
        (HERE / "vhs" / "tui.tape", OUT_DIR / "tui.webm"),
        (HERE / "vhs" / "top.tape", OUT_DIR / "top.webm"),
        (HERE / "vhs" / "demo.tape", OUT_DIR / "terminal_ui.webm"),
    ]
    for tape, video in pairs:
        if not video.exists():
            print(f"skip keystrokes (missing): {video.name}")
            continue
        tmp = video.with_suffix(".overlay.webm")
        overlay(tape, video, tmp)
        tmp.replace(video)
        print(f"baked keystroke toasts into {video.name} ({video.stat().st_size} bytes)")


def stage_verify() -> None:
    failures: list[str] = []
    if not OUT_DIR.exists():
        print("ERROR: output dir missing", file=sys.stderr)
        sys.exit(1)
    pngs = sorted(OUT_DIR.glob("*.png"))
    webms = sorted(OUT_DIR.glob("*.webm"))
    if not pngs:
        failures.append("no PNGs produced")
    if not webms:
        failures.append("no WebMs produced")
    for p in pngs:
        size = p.stat().st_size
        if size < 1024:
            failures.append(f"{p.name}: only {size} bytes")
        elif size > PNG_BUDGET:
            failures.append(f"{p.name}: {size} bytes exceeds PNG budget {PNG_BUDGET}")
        # PIL decode check (optional; skip if Pillow not present)
        try:
            from PIL import Image  # noqa: PLC0415

            with Image.open(p) as img:
                img.verify()
        except ModuleNotFoundError:
            pass
        except Exception as e:
            failures.append(f"{p.name}: PIL decode failed: {e}")
    for w in webms:
        size = w.stat().st_size
        if size < 1024:
            failures.append(f"{w.name}: only {size} bytes")
        elif size > WEBM_BUDGET:
            failures.append(f"{w.name}: {size} bytes exceeds WebM budget {WEBM_BUDGET}")
    print(f"\n{len(pngs)} PNGs, {len(webms)} WebMs in {OUT_DIR}")
    for p in pngs + webms:
        print(f"  {p.name:32s} {p.stat().st_size:>10d} bytes")
    if failures:
        print("\nVERIFICATION FAILED:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        sys.exit(1)


PUBLISH_PNGS = {
    "webui-overview-1d.png": "screenshot.png",
}
PUBLISH_WEBMS = {
    "web_ui.webm": "web_ui.webm",
    "terminal_ui.webm": "terminal_ui.webm",
}


def stage_publish() -> None:
    docs_dir = REPO_ROOT / "docs"
    for src_name, dst_name in PUBLISH_PNGS.items():
        src = OUT_DIR / src_name
        if not src.exists():
            print(f"skip publish (missing): {src_name}")
            continue
        dst = docs_dir / dst_name
        shutil.copy2(src, dst)
        print(f"published {dst.relative_to(REPO_ROOT)}")
    for src_name, dst_name in PUBLISH_WEBMS.items():
        src = OUT_DIR / src_name
        if not src.exists():
            print(f"skip publish (missing): {src_name}")
            continue
        dst = docs_dir / dst_name
        shutil.copy2(src, dst)
        print(f"published {dst.relative_to(REPO_ROOT)} ({dst.stat().st_size} bytes)")


# ---------------------------------------------------------------- main


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--skip-seed", action="store_true")
    p.add_argument("--skip-webui", action="store_true")
    p.add_argument("--skip-tui", action="store_true")
    p.add_argument("--skip-top", action="store_true")
    p.add_argument("--skip-demo", action="store_true")
    p.add_argument("--skip-keystrokes", action="store_true")
    p.add_argument("--skip-verify", action="store_true")
    p.add_argument("--publish", action="store_true", help="copy curated subset onto docs/")
    args = p.parse_args()

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    needs_vhs = not (args.skip_tui and args.skip_top and args.skip_demo)
    if needs_vhs:
        vhs = _check_tool("vhs", "see https://github.com/charmbracelet/vhs#installation or docs/screenshots/README.md")
        _check_tool("ttyd", "apt install ttyd  (or brew install ttyd)")
        _check_tool("ffmpeg", "apt install ffmpeg")
    else:
        vhs = ""

    if not args.skip_seed:
        stage_seed()
    if not args.skip_webui:
        stage_webui()
    if not args.skip_tui:
        stage_tui(vhs)
    if not args.skip_top:
        stage_top(vhs)
    if not args.skip_demo:
        stage_demo(vhs)
    if not args.skip_keystrokes:
        stage_keystrokes()
    if not args.skip_verify:
        stage_verify()
    if args.publish:
        stage_publish()

    print("\nDone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
