#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
Overlay a stacked keystroke toast on a VHS-recorded WebM.

VHS doesn't render visible keystrokes, so we parse the .tape file to
estimate when each user-facing keypress happens, scale the timeline to
match the actual recorded video duration (VHS doesn't promise a 1:1
mapping between tape-time and output-time), then run ffmpeg drawtext
to render labelled badges in the bottom-right corner of the video.

Toasts stack: each one has a fixed on-screen lifetime, and when a new
press fires while older toasts are still visible, the older toasts
shift upward to make room. This means rapid-fire presses (Right Right
Right ...) stay legible instead of flashing past as a single label.
"""

import argparse
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

KEY_LABELS: dict[str, str] = {
    "Enter": "Enter \u21b5",
    "Tab": "Tab \u21e5",
    "Space": "Space",
    "Backspace": "Backspace",
    "Escape": "Esc",
    "Up": "Up \u2191",
    "Down": "Down \u2193",
    "Left": "Left \u2190",
    "Right": "Right \u2192",
    "PageUp": "PgUp",
    "PageDown": "PgDn",
    "Home": "Home",
    "End": "End",
    "Delete": "Del",
}

# Default time between presses when "Key 3" is used without "@<time>".
DEFAULT_KEY_GAP_S = 0.18

# How long each toast stays fully on screen (before fade-out begins).
TOAST_LIFE_S = 2.8

# Animation timings.
T_FADE_IN = 0.20  # alpha ramp at birth
T_SLIDE_IN = 0.32  # how long the slide-up-from-below animation takes
T_FADE_OUT = 0.45  # fade out + slide off at death
T_SLOT = 0.28  # slot-shift interpolation when a newer toast appears
T_HIGHLIGHT = 0.55  # how long the bright glow halo lingers after birth
SLIDE_DIST = 320  # how far (px) a dying toast slides right before going off-screen
SLIDE_IN_DIST = 130  # how far (px) below its final position a new toast starts

# Maximum simultaneously visible toasts (older ones drop off the top).
MAX_STACK = 16

# Visual sizing.
FONT_SIZE = 22
LINE_HEIGHT = 48  # vertical pitch between stacked toasts (px)
MARGIN = 32

# Highlight halo: rendered first, larger box border than the main pass
# so the outer rim shows as a glow ring around the toast during birth.
HIGHLIGHT_BORDER = 26  # vs main's boxborderw=14 -> 12px halo on every side
HIGHLIGHT_COLOR = "0x7dcfff"  # cyan accent matching the TokyoNight theme
MARGIN = 32

FONT_CANDIDATES: list[str] = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationMono-Bold.ttf",
    "/usr/share/fonts/TTF/DejaVuSansMono-Bold.ttf",
]


@dataclass
class Event:
    label: str
    t: float  # tape-time (Show-region only), seconds


def _parse_duration(tok: str) -> float:
    m = re.match(r"^(\d+(?:\.\d+)?)(ms|s)$", tok)
    if not m:
        return 0.0
    v = float(m.group(1))
    return v / 1000.0 if m.group(2) == "ms" else v


def parse_tape(path: Path) -> tuple[list[Event], float]:
    """Return (events, total_show_seconds). Hide-region time is excluded."""
    events: list[Event] = []
    typing_speed = 0.05
    hidden = False
    t = 0.0
    key_re = re.compile(
        r"^(Enter|Tab|Escape|Backspace|Space|Up|Down|Left|Right|"
        r"PageUp|PageDown|Home|End|Delete)"
        r"(?:@(\S+))?(?:\s+(\d+))?$"
    )
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line == "Hide":
            hidden = True
            continue
        if line == "Show":
            hidden = False
            continue
        m = re.match(r"^Set\s+TypingSpeed\s+(\S+)$", line)
        if m:
            typing_speed = _parse_duration(m.group(1))
            continue
        m = re.match(r"^Sleep\s+(\S+)$", line)
        if m:
            if not hidden:
                t += _parse_duration(m.group(1))
            continue
        m = re.match(r'^Type(?:@(\S+))?\s+"(.*)"$', line)
        if m:
            speed = _parse_duration(m.group(1)) if m.group(1) else typing_speed
            text = m.group(2)
            if not hidden:
                for ch in text:
                    label = ch if ch != " " else "Space"
                    events.append(Event(label, t))
                    t += speed
            continue
        m = key_re.match(line)
        if m:
            key, gap, count = m.group(1), m.group(2), m.group(3)
            gap_s = _parse_duration(gap) if gap else DEFAULT_KEY_GAP_S
            n = int(count) if count else 1
            label = KEY_LABELS.get(key, key)
            for _ in range(n):
                if not hidden:
                    events.append(Event(label, t))
                t += gap_s
            continue
        # ignore Set FontSize / Output / Screenshot / etc.
    return events, t


def _ffprobe_duration(path: Path) -> float:
    out = subprocess.check_output(
        [
            "ffprobe",
            "-v",
            "error",
            "-show_entries",
            "format=duration",
            "-of",
            "default=nw=1:nk=1",
            str(path),
        ],
        text=True,
    ).strip()
    return float(out)


def _pick_font() -> str | None:
    for cand in FONT_CANDIDATES:
        if Path(cand).exists():
            return cand
    return None


def _escape_drawtext_text(s: str) -> str:
    return s.replace("\\", "\\\\").replace(":", r"\:").replace("'", r"\'")


def _slot_transitions(event_idx: int, starts: list[float], life: float) -> list[tuple[float, int]]:
    """Return sorted [(time, delta_slot)] caused by newer events.

    Slot 0 = bottom (most recent right now). Newer event firing pushes
    us up by +1 (slot delta +1 at its start). Newer event expiring
    drops us back by -1 (delta -1 at its end), but only if it dies
    before we do.
    """
    s_i = starts[event_idx]
    e_i = s_i + life
    out: list[tuple[float, int]] = []
    for j in range(event_idx + 1, len(starts)):
        s_j = starts[j]
        if s_j >= e_i:
            break
        if s_j > s_i:
            out.append((s_j, +1))
            e_j = s_j + life
            if e_j < e_i:
                out.append((e_j, -1))
    out.sort()
    return out


def _max_slot(transitions: list[tuple[float, int]]) -> int:
    """Highest slot the toast ever occupies (0 if no newer siblings)."""
    slot, peak = 0, 0
    for _t, d in transitions:
        slot += d
        if slot > peak:
            peak = slot
    return peak


def _build_slot_expr(transitions: list[tuple[float, int]]) -> str:
    """ffmpeg expression for fractional slot(t).

    Each transition (tc, d) contributes a smooth step:
        d * clip((t - tc) / T_SLOT, 0, 1)
    so a +1 at tc ramps slot from 0 -> 1 over T_SLOT seconds.
    """
    if not transitions:
        return "0"
    terms = []
    for tc, d in transitions:
        terms.append(f"({d})*max(0\\,min(1\\,(t-{tc:.3f})/{T_SLOT}))")
    return "+".join(terms)


def overlay(tape: Path, video: Path, out: Path, font: str | None = None) -> None:
    events, total_tape_show = parse_tape(tape)
    if not events:
        shutil.copy2(video, out)
        return
    actual = _ffprobe_duration(video)
    # Scale show-time onto recorded duration so the trailing Sleep is accounted for.
    scale = actual / total_tape_show if total_tape_show > 0 else 1.0
    starts = [ev.t * scale for ev in events]
    if font is None:
        font = _pick_font()

    parts: list[str] = []
    for i, ev in enumerate(events):
        s = starts[i]
        e = s + TOAST_LIFE_S
        transitions = _slot_transitions(i, starts, TOAST_LIFE_S)
        if _max_slot(transitions) >= MAX_STACK:
            continue
        text = _escape_drawtext_text(ev.label)
        font_part = f"fontfile='{font}':" if font else ""
        slot_expr = _build_slot_expr(transitions)
        # y: bottom-anchored; rises from below the frame during T_SLIDE_IN.
        slide_in = f"+{SLIDE_IN_DIST}*max(0\\,1-(t-{s:.3f})/{T_SLIDE_IN})"
        y_expr = f"h-th-{MARGIN}-({slot_expr})*{LINE_HEIGHT}{slide_in}"
        # x: right-aligned, slides right by SLIDE_DIST during fade-out.
        slide_start = e - T_FADE_OUT
        x_expr = f"w-tw-{MARGIN}+max(0\\,(t-{slide_start:.3f})/{T_FADE_OUT})*{SLIDE_DIST}"
        # alpha: linear fade in then fade out (min of the two ramps).
        alpha_expr = f"min(min(1\\,(t-{s:.3f})/{T_FADE_IN})\\,max(0\\,({e:.3f}-t)/{T_FADE_OUT}))"
        # Glow halo pass (rendered first; main pass covers the centre).
        glow_alpha = f"min({alpha_expr}\\,max(0\\,1-(t-{s:.3f})/{T_HIGHLIGHT}))"
        glow_end = s + T_HIGHLIGHT
        parts.append(
            f"drawtext={font_part}text='{text}':"
            f"fontcolor=white:fontsize={FONT_SIZE}:"
            f"box=1:boxcolor={HIGHLIGHT_COLOR}@0.9:boxborderw={HIGHLIGHT_BORDER}:"
            f"alpha='{glow_alpha}':"
            f"x='{x_expr}':y='{y_expr}':"
            f"enable='between(t,{s:.3f},{glow_end:.3f})'"
        )
        # Main pass.
        parts.append(
            f"drawtext={font_part}text='{text}':"
            f"fontcolor=white:fontsize={FONT_SIZE}:"
            "box=1:boxcolor=0x141828@0.85:boxborderw=14:"
            f"alpha='{alpha_expr}':"
            f"x='{x_expr}':y='{y_expr}':"
            f"enable='between(t,{s:.3f},{e:.3f})'"
        )
    if not parts:
        shutil.copy2(video, out)
        return
    vf = ",".join(parts)
    subprocess.check_call(
        [
            "ffmpeg",
            "-y",
            "-loglevel",
            "error",
            "-i",
            str(video),
            "-vf",
            vf,
            "-c:v",
            "libvpx-vp9",
            "-b:v",
            "0",
            "-crf",
            "32",
            "-an",
            str(out),
        ]
    )


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("tape", type=Path)
    p.add_argument("video", type=Path)
    p.add_argument("out", type=Path)
    p.add_argument("--font", default=None)
    args = p.parse_args()
    overlay(args.tape, args.video, args.out, args.font)
    return 0


if __name__ == "__main__":
    sys.exit(main())
