#!/usr/bin/env bash
# Build and install iovisor/bcc v0.37.0 from source.
#
# The Ubuntu package (0.35.0) fails to JIT-compile against the 7.0 kernel headers
# (undeclared BPF_F_CPU, no member 'ns_id'); v0.37.0 (supports kernel up to 7.1)
# compiles and runs. Installs libbcc, the tools, and the python bindings to
# system paths. Targets Ubuntu 26.04 (LLVM 21). Idempotent: no-op if already
# installed. Invoked by the bcc adapters in adapters.py.
set -euo pipefail
BCC_VER=v0.37.0
SRC="${1:-$(cd "$(dirname "$0")/.." && pwd)/downloads/bcc-src}"

if [ -f /usr/local/lib/libbcc.so ] && [ -f /usr/local/share/bcc/tools/tcplife ] \
   && python3 -c "import bcc" 2>/dev/null; then
    echo "bcc already installed"
    exit 0
fi

export DEBIAN_FRONTEND=noninteractive
apt-get install -y bison build-essential cmake flex git libedit-dev \
    llvm-21-dev libclang-21-dev clang-21 libpolly-21-dev python3 \
    python3-setuptools zlib1g-dev libelf-dev libfl-dev zip

rm -rf "$SRC"
git clone https://github.com/iovisor/bcc.git "$SRC"
git -C "$SRC" checkout "$BCC_VER"
mkdir -p "$SRC/build"
cd "$SRC/build"
cmake .. -DCMAKE_BUILD_TYPE=Release -DPYTHON_CMD=python3
make -j"$(nproc)"
make install
ldconfig
python3 -c "import bcc" && echo "bcc $BCC_VER installed"
