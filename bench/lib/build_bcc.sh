#!/usr/bin/env bash
# Build and install iovisor/bcc from source at the pinned tag below.
#
# The Ubuntu package fails to JIT-compile against the 7.0 kernel headers
# (undeclared BPF_F_CPU, no member 'ns_id'); the pinned tag
# compiles and runs. Installs libbcc, the tools, and the python bindings under
# PREFIX. Targets Ubuntu 26.04 (LLVM 21). Idempotent: no-op when the
# pinned version is already installed. Invoked by the bcc adapters in adapters.py.
set -euo pipefail
BCC_VER=v0.37.0
PREFIX=/usr/local  # where the adapters look (LD_LIBRARY_PATH, UP_TOOLS)
SRC="${1:-$(cd "$(dirname "$0")/.." && pwd)/downloads/bcc-src}"

# Skip only when the PINNED library is installed where the adapters read it.
# Deliberately does NOT test `import bcc`: Ubuntu's python3-bpfcc provides that
# module, so it succeeds even when nothing was built here.
if [ -f "$PREFIX/share/bcc/tools/tcplife" ] \
   && [ "$(readlink -f "$PREFIX/lib/libbcc.so" 2>/dev/null)" = "$PREFIX/lib/libbcc.so.${BCC_VER#v}" ]; then
    echo "bcc ${BCC_VER} already installed in $PREFIX"
    exit 0
fi

export DEBIAN_FRONTEND=noninteractive
# refresh the package lists first: a fresh cloud image can ship empty/stale lists,
# and the versioned LLVM packages below then fail to resolve
apt-get update
apt-get install -y bison build-essential cmake flex git libedit-dev \
    llvm-21-dev libclang-21-dev clang-21 libpolly-21-dev python3 \
    python3-setuptools zlib1g-dev libelf-dev libfl-dev zip

rm -rf "$SRC"
git clone https://github.com/iovisor/bcc.git "$SRC"
git -C "$SRC" checkout "$BCC_VER"
mkdir -p "$SRC/build"
cd "$SRC/build"
# CMAKE_INSTALL_PREFIX must be passed EXPLICITLY. bcc's CMakeLists force-overrides
# it to /usr whenever it was left at cmake's default (CMakeLists.txt:
# `if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT) set(... "/usr" ... FORCE)`), so a
# plain `cmake ..` builds and installs successfully into /usr while the adapters --
# which read $PREFIX -- see nothing and report the tool as unbuildable.
cmake .. -DCMAKE_BUILD_TYPE=Release -DPYTHON_CMD=python3 -DCMAKE_INSTALL_PREFIX="$PREFIX"
make -j"$(nproc)"
make install
ldconfig

# Verify what the adapters will actually use, so a build that "succeeded" but
# landed elsewhere fails here, where the reason is visible, instead of surfacing
# later as a version mismatch.
missing=""
[ "$(readlink -f "$PREFIX/lib/libbcc.so" 2>/dev/null)" = "$PREFIX/lib/libbcc.so.${BCC_VER#v}" ] \
    || missing="$missing $PREFIX/lib/libbcc.so.${BCC_VER#v}"
for t in tcplife tcpconnect tcptop; do
    [ -f "$PREFIX/share/bcc/tools/$t" ] || missing="$missing $PREFIX/share/bcc/tools/$t"
done
if [ -n "$missing" ]; then
    echo "ERROR: bcc $BCC_VER built but these are missing:$missing" >&2
    echo "       installed prefix was: $(grep -m1 '^CMAKE_INSTALL_PREFIX' CMakeCache.txt)" >&2
    exit 1
fi

# The tools are python scripts: report which bindings the interpreter resolves.
# The pinned libbcc is pinned by LD_LIBRARY_PATH, but a distro python3-bpfcc can
# still shadow the bindings built here, which would run the pinned library through
# an older wrapper.
bindings="$(python3 -c 'import bcc; print(bcc.__file__)' 2>/dev/null || echo none)"
case "$bindings" in
    "$PREFIX"/*) ;;
    *) echo "WARNING: 'import bcc' resolves to $bindings, outside $PREFIX;" >&2
       echo "         Ubuntu's python3-bpfcc is shadowing the bindings built here." >&2 ;;
esac
echo "bcc $BCC_VER installed in $PREFIX (bindings: $bindings)"
