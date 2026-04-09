"""Hatchling build hook to compile BPF program during wheel build."""

import os
import platform
import subprocess

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class BPFBuildHook(BuildHookInterface):
    PLUGIN_NAME = "bpf-build"

    def initialize(self, version, build_data):
        if self.target_name != "wheel":
            return

        bpf_src_dir = os.path.join(self.root, "picosnitch", "bpf")
        bpf_src = os.path.join(bpf_src_dir, "picosnitch.bpf.c")
        bpf_obj = os.path.join(bpf_src_dir, "picosnitch.bpf.o")

        if os.path.exists(bpf_obj):
            # Already compiled (e.g. CI provided a pre-built object)
            build_data["shared_data"]["bpf_obj"] = bpf_obj
            return

        if not os.path.exists(bpf_src):
            raise RuntimeError(f"BPF source not found: {bpf_src}")

        # Generate vmlinux.h if needed
        vmlinux_h = os.path.join(bpf_src_dir, "vmlinux.h")
        if not os.path.exists(vmlinux_h):
            if not os.path.exists("/sys/kernel/btf/vmlinux"):
                raise RuntimeError(
                    "Cannot compile BPF: /sys/kernel/btf/vmlinux not found.\n"
                    "Either provide a pre-compiled bpf/picosnitch.bpf.o or "
                    "build on a kernel with CONFIG_DEBUG_INFO_BTF=y"
                )
            result = subprocess.run(
                ["bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c"],
                capture_output=True, text=True, check=True,
            )
            with open(vmlinux_h, "w") as f:
                f.write(result.stdout)

        # Determine target architecture
        arch = os.environ.get("BPF_TARGET_ARCH", platform.machine())
        arch_map = {"x86_64": "x86", "aarch64": "arm64"}
        bpf_target = arch_map.get(arch, arch)

        # Compile
        subprocess.run(
            [
                "clang", "-g", "-O2", "-target", "bpf",
                f"-D__TARGET_ARCH_{bpf_target}",
                "-Wall", "-Werror",
                f"-I{bpf_src_dir}",
                "-c", bpf_src, "-o", bpf_obj,
            ],
            check=True,
        )

        # Strip debug info (optional, non-fatal)
        try:
            subprocess.run(["llvm-strip", "-g", bpf_obj], capture_output=True, check=True)
        except (FileNotFoundError, subprocess.CalledProcessError):
            pass

        build_data["shared_data"]["bpf_obj"] = bpf_obj
