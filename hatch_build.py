"""Hatchling build hook to compile BPF program during wheel build."""

import os
import platform
import subprocess

from hatchling.builders.hooks.plugin.interface import BuildHookInterface  # ty: ignore[unresolved-import]


class BPFBuildHook(BuildHookInterface):
    PLUGIN_NAME = "bpf-build"

    def initialize(self, version, build_data):
        if self.target_name != "wheel":
            return

        # Skip BPF compilation for editable installs (used by `uv sync` /
        # dev workflows). The BPF object is only needed for runtime, not
        # for importing the package during development or testing.
        if version == "editable" or os.environ.get("PICOSNITCH_SKIP_BPF_BUILD"):
            return

        # The wheel has no C extension linked against glibc -- it ships a
        # precompiled BPF object (kernel bytecode, no userspace linkage) plus
        # pure-Python code that dlopen's libbpf.so via ctypes at runtime.
        arch = os.environ.get("PICOSNITCH_BPF_TARGET_ARCH", platform.machine())
        plat_tags = {
            "x86_64": "manylinux_2_34_x86_64",
            "aarch64": "manylinux_2_34_aarch64",
        }
        if arch not in plat_tags:
            raise RuntimeError(f"Unsupported arch for BPF build: {arch}")
        build_data["pure_python"] = False
        build_data["tag"] = f"py3-none-{plat_tags[arch]}"

        bpf_src_dir = os.path.join(self.root, "src", "picosnitch", "bpf")
        bpf_src = os.path.join(bpf_src_dir, "picosnitch.bpf.c")
        bpf_obj = os.path.join(bpf_src_dir, "picosnitch.bpf.o")

        def register(obj_path):
            build_data.setdefault("force_include", {})[obj_path] = "picosnitch/bpf/picosnitch.bpf.o"

        if not os.path.exists(bpf_src):
            if os.path.exists(bpf_obj):
                # No source, but a pre-built object exists (e.g. CI provided it)
                register(bpf_obj)
                return
            raise RuntimeError(f"BPF source not found: {bpf_src}")

        if os.path.exists(bpf_obj) and os.path.getmtime(bpf_obj) >= os.path.getmtime(bpf_src):
            # Object up to date with source; reuse it.
            register(bpf_obj)
            return

        # Kernel-style target arch name (matches arch/* in the kernel tree and
        # libbpf's __TARGET_ARCH_* macro from bpf_tracing.h).
        bpf_target_arch = {"x86_64": "x86", "aarch64": "arm64"}[arch]

        # Select vmlinux.h with this precedence:
        #   1. An existing src/picosnitch/bpf/vmlinux.h
        #   2. Our vendored per-arch header
        #   3. bpftool BTF dump from the running kernel
        vmlinux_h = os.path.join(bpf_src_dir, "vmlinux.h")
        vendored_vmlinux = os.path.join(bpf_src_dir, f"vmlinux_{bpf_target_arch}.h")
        if os.path.exists(vmlinux_h):
            pass
        elif os.path.exists(vendored_vmlinux):
            import shutil

            shutil.copyfile(vendored_vmlinux, vmlinux_h)
        else:
            if not os.path.exists("/sys/kernel/btf/vmlinux"):
                raise RuntimeError(
                    f"Cannot compile BPF: no vendored vmlinux_{bpf_target_arch}.h and "
                    "/sys/kernel/btf/vmlinux not available.\n"
                    "Either provide a pre-compiled bpf/picosnitch.bpf.o or build "
                    "on a kernel with CONFIG_DEBUG_INFO_BTF=y"
                )
            result = subprocess.run(
                ["bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c"],
                capture_output=True,
                text=True,
                check=True,
            )
            with open(vmlinux_h, "w") as f:
                f.write(result.stdout)

        # Compile
        subprocess.run(
            [
                "clang",
                "-g",
                "-O2",
                "-target",
                "bpf",
                f"-D__TARGET_ARCH_{bpf_target_arch}",
                "-Wall",
                "-Werror",
                # Anonymous forward decls inside structs in libbpf's curated vmlinux.h
                # trip -Wmissing-declarations; harmless for BPF compilation.
                "-Wno-missing-declarations",
                f"-I{bpf_src_dir}",
                "-c",
                bpf_src,
                "-o",
                bpf_obj,
            ],
            check=True,
        )

        # Strip debug info (optional, non-fatal)
        try:
            subprocess.run(["llvm-strip", "-g", bpf_obj], capture_output=True, check=True)
        except (FileNotFoundError, subprocess.CalledProcessError):
            pass

        register(bpf_obj)
