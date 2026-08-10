#!/usr/bin/env bash
# Compile all benchmark C helpers into bench/bin.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p bin
# build deps (idempotent): gcc + liburing for benchuring
{ command -v gcc && dpkg -s liburing-dev; } >/dev/null 2>&1 || \
    apt-get install -y build-essential liburing-dev
# -fno-strict-aliasing: the packet crafters (benchpacket/benchraw/benchicmp) cast a
# byte buffer to packed header structs, store 32-bit addresses, then checksum through
# a uint16_t*. Reading those stores through a differently-typed lvalue is undefined,
# and at -O2 a compiler is free to reorder the checksum load above the address store
# (observed: frames leaving with a stale-zero-address checksum the peer drops). This
# flag makes the type-punning well-defined so the emitted frames are always valid.
CFLAGS="-O2 -Wall -fno-strict-aliasing"
gcc $CFLAGS -o bin/benchserver gen/benchserver.c
gcc $CFLAGS -o bin/benchgen    gen/benchgen.c
gcc $CFLAGS -o bin/benchicmp   gen/benchicmp.c
gcc $CFLAGS -o bin/benchraw    gen/benchraw.c
gcc $CFLAGS -o bin/benchpacket gen/benchpacket.c
gcc $CFLAGS -o bin/benchuring  gen/benchuring.c -luring
# static build for the in-container scenario (runs on any base image)
gcc $CFLAGS -static -o bin/benchgen_static gen/benchgen.c || echo "WARN: static build failed (s17 in-container will record errors)"
echo "built: $(ls bin/)"
