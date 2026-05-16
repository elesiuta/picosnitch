#!/usr/bin/env bash
# Convenience wrapper for the offline screenshot pipeline.
#
# Uses the repo's uv-managed environment (.venv) and the `dev` dependency
# group from pyproject.toml. Optionally bootstraps a local copy of VHS
# into docs/screenshots/.bin/ when not already on PATH.
#
# Usage:
#   bash docs/generate_screenshots.sh             # generate everything into docs/screenshots/out/
#   bash docs/generate_screenshots.sh --publish   # also overwrite docs/{screenshot.png,web_ui.gif,terminal_ui.gif}
#
# Pass-through flags (forwarded to generate_screenshots.py):
#   --skip-seed --skip-webui --skip-tui --skip-top --skip-demo --skip-verify

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCREENSHOTS_DIR="$REPO_ROOT/docs/screenshots"
BIN_DIR="$SCREENSHOTS_DIR/.bin"

cd "$REPO_ROOT"

if ! command -v uv >/dev/null 2>&1; then
    echo "ERROR: uv not found. Install from https://docs.astral.sh/uv/getting-started/installation/" >&2
    exit 2
fi

# 1. Sync the dev dependency group + editable install of picosnitch.
echo "Syncing uv environment (dev group)"
uv sync --group dev --quiet

# Install Playwright chromium browser (idempotent; cached under ~/.cache/ms-playwright).
if ! ls "$HOME/.cache/ms-playwright/chromium-"* >/dev/null 2>&1; then
    echo "Installing Playwright chromium browser"
    uv run playwright install chromium
fi

# 2. VHS / ttyd / ffmpeg --------------------------------------------------
mkdir -p "$BIN_DIR"
export PATH="$BIN_DIR:$PATH"

if ! command -v vhs >/dev/null 2>&1; then
    # Pinned VHS version + SHA256; bump both together. amd64-only.
    VHS_VERSION="0.7.2"
    VHS_SHA256="20c677ce9abfd4b4bb7ba883e66c6440758bea700f627f9b5e8297c083fcff4f"
    UNAME_M="$(uname -m)"
    if [[ "$UNAME_M" != "x86_64" && "$UNAME_M" != "amd64" ]]; then
        echo "VHS bootstrap only supports x86_64/amd64 (got: $UNAME_M)." >&2
        echo "Install VHS manually from https://github.com/charmbracelet/vhs" >&2
        exit 2
    fi
    VHS_TARBALL="vhs_${VHS_VERSION}_Linux_x86_64.tar.gz"
    VHS_URL="https://github.com/charmbracelet/vhs/releases/download/v${VHS_VERSION}/${VHS_TARBALL}"
    echo "Downloading VHS $VHS_VERSION from $VHS_URL"
    curl -fsSL "$VHS_URL" -o "$BIN_DIR/$VHS_TARBALL"
    echo "$VHS_SHA256  $BIN_DIR/$VHS_TARBALL" | sha256sum --check --status || {
        echo "ERROR: VHS tarball SHA256 mismatch (expected $VHS_SHA256)" >&2
        echo "       got: $(sha256sum "$BIN_DIR/$VHS_TARBALL" | awk '{print $1}')" >&2
        rm -f "$BIN_DIR/$VHS_TARBALL"
        exit 2
    }
    tar -xzf "$BIN_DIR/$VHS_TARBALL" -C "$BIN_DIR" --strip-components=1 "$(tar -tzf "$BIN_DIR/$VHS_TARBALL" | grep -m1 '/vhs$')"
    chmod +x "$BIN_DIR/vhs"
    rm -f "$BIN_DIR/$VHS_TARBALL"
fi

missing=()
command -v ttyd   >/dev/null 2>&1 || missing+=("ttyd")
command -v ffmpeg >/dev/null 2>&1 || missing+=("ffmpeg")
if (( ${#missing[@]} )); then
    echo "Missing required tools: ${missing[*]}" >&2
    echo "Install on Debian/Ubuntu: sudo apt install ${missing[*]}" >&2
    exit 2
fi

# 3. Run the orchestrator -------------------------------------------------
exec uv run python "$SCREENSHOTS_DIR/generate_screenshots.py" "$@"
