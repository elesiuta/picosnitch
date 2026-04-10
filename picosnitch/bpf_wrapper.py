#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta
"""
libbpf wrapper for picosnitch - replaces BCC dependency
Uses ctypes to interface with libbpf.so directly for BPF CO-RE support
"""

import ctypes
import ctypes.util
import errno
import os
import platform
import re
import subprocess
from typing import Callable, Dict, Optional


def _detect_distro() -> str:
    """Detect Linux distribution for better error messages."""
    try:
        with open("/etc/os-release") as f:
            return f.read().lower()
    except Exception:
        return ""


def _get_install_instructions() -> str:
    """Get distro-specific install instructions for libbpf."""
    distro = _detect_distro()

    instructions = "\nInstall libbpf:\n"
    if "ubuntu" in distro or "debian" in distro or "pop" in distro or "mint" in distro:
        instructions += "  sudo apt install libbpf1\n"
    elif "fedora" in distro or "rhel" in distro or "centos" in distro or "rocky" in distro or "alma" in distro:
        instructions += "  sudo dnf install libbpf\n"
    elif "arch" in distro or "manjaro" in distro or "endeavour" in distro:
        instructions += "  sudo pacman -S libbpf\n"
    elif "opensuse" in distro or "suse" in distro:
        instructions += "  sudo zypper install libbpf1\n"
    elif "gentoo" in distro:
        instructions += "  sudo emerge dev-libs/libbpf\n"
    elif "void" in distro:
        instructions += "  sudo xbps-install libbpf\n"
    else:
        instructions += """  Ubuntu/Debian: sudo apt install libbpf1
  Fedora/RHEL:   sudo dnf install libbpf
  Arch Linux:    sudo pacman -S libbpf
  openSUSE:      sudo zypper install libbpf1
"""
    return instructions


def _check_kernel_btf() -> bool:
    """Check if kernel has BTF support."""
    return os.path.exists("/sys/kernel/btf/vmlinux")


def _check_bpf_filesystem() -> bool:
    """Check if BPF filesystem is mounted."""
    return os.path.exists("/sys/fs/bpf")


def check_bpf_requirements() -> None:
    """
    Check all BPF requirements and raise RuntimeError with helpful messages if not met.
    Call this before attempting to load BPF programs.
    """
    errors = []

    # Check kernel BTF support
    if not _check_kernel_btf():
        errors.append("Kernel BTF not found at /sys/kernel/btf/vmlinux\n  Your kernel must be built with CONFIG_DEBUG_INFO_BTF=y\n  Most modern distro kernels (5.8+) have this enabled by default")

    # Check BPF filesystem
    if not _check_bpf_filesystem():
        errors.append("BPF filesystem not mounted at /sys/fs/bpf\n  Try: sudo mount -t bpf bpf /sys/fs/bpf")

    # Check root/capabilities
    if os.geteuid() != 0:
        errors.append("Must run as root (BPF requires CAP_BPF and CAP_PERFMON)\n  Try: sudo picosnitch start")

    if errors:
        raise RuntimeError("BPF requirements not met:\n\n" + "\n\n".join(errors))


def compile_bpf(output_path: Optional[str] = None, arch: Optional[str] = None) -> str:
    """
    Compile the BPF CO-RE program from source.

    Generates vmlinux.h from the running kernel's BTF and compiles picosnitch.bpf.c.
    Used by CI/build systems and as a fallback when no pre-compiled .bpf.o is found.

    Args:
        output_path: Where to write the .bpf.o file. Defaults to picosnitch/bpf/picosnitch.bpf.o
        arch: Target architecture (x86_64, aarch64). Defaults to current machine.

    Returns:
        Path to the compiled .bpf.o file.
    """
    if arch is None:
        arch = platform.machine()

    arch_to_bpf_target = {
        "x86_64": "x86",
        "aarch64": "arm64",
    }
    bpf_target_arch = arch_to_bpf_target.get(arch, arch)

    bpf_src_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bpf")
    bpf_src = os.path.join(bpf_src_dir, "picosnitch.bpf.c")
    vmlinux_h = os.path.join(bpf_src_dir, "vmlinux.h")

    if output_path is None:
        output_path = os.path.join(bpf_src_dir, "picosnitch.bpf.o")

    if not os.path.exists(bpf_src):
        raise FileNotFoundError(f"BPF source not found: {bpf_src}")

    # Generate vmlinux.h if not present
    if not os.path.exists(vmlinux_h):
        if not os.path.exists("/sys/kernel/btf/vmlinux"):
            raise RuntimeError("Cannot generate vmlinux.h: /sys/kernel/btf/vmlinux not found.\nYour kernel must be built with CONFIG_DEBUG_INFO_BTF=y")
        try:
            result = subprocess.run(["bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c"], capture_output=True, text=True, check=True)
            with open(vmlinux_h, "w") as f:
                f.write(result.stdout)
        except FileNotFoundError:
            raise RuntimeError("bpftool not found. Install bpftool to compile BPF programs.")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to generate vmlinux.h: {e.stderr}")

    # Compile BPF program
    clang_cmd = [
        "clang",
        "-g",
        "-O2",
        "-target",
        "bpf",
        f"-D__TARGET_ARCH_{bpf_target_arch}",
        "-Wall",
        "-Werror",
        f"-I{bpf_src_dir}",
        "-c",
        bpf_src,
        "-o",
        output_path,
    ]
    try:
        subprocess.run(clang_cmd, capture_output=True, text=True, check=True)
    except FileNotFoundError:
        raise RuntimeError("clang not found. Install clang to compile BPF programs.")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"BPF compilation failed:\n{e.stderr}")

    # Strip debug info to reduce size
    try:
        subprocess.run(["llvm-strip", "-g", output_path], capture_output=True, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        pass  # Non-fatal: llvm-strip is optional

    return output_path


def find_bpf_object() -> str:
    """
    Find the pre-compiled BPF object file, or compile it as a fallback.

    Returns:
        Path to the .bpf.o file.
    """
    arch = platform.machine()
    bpf_filename = "picosnitch.bpf.o"
    bpf_filename_arch = f"picosnitch.bpf.{arch}.o"
    _pkg_dir = os.path.dirname(os.path.abspath(__file__))
    import sys

    search_paths = [
        os.path.join(_pkg_dir, "bpf", bpf_filename_arch),
        os.path.join(_pkg_dir, "bpf", bpf_filename),
        f"/usr/share/picosnitch/bpf/{bpf_filename_arch}",
        f"/usr/share/picosnitch/bpf/{bpf_filename}",
        os.path.join(sys.prefix, "share", "picosnitch", "bpf", bpf_filename_arch),
        os.path.join(sys.prefix, "share", "picosnitch", "bpf", bpf_filename),
    ]
    for path in search_paths:
        if os.path.exists(path):
            return path

    # Fallback: compile from source
    bpf_src = os.path.join(_pkg_dir, "bpf", "picosnitch.bpf.c")
    if os.path.exists(bpf_src):
        return compile_bpf()

    raise FileNotFoundError(f"BPF object file not found for {arch}. Searched: {search_paths}")


# Event structures matching BPF code - must be packed and match exactly
class ExecEvent(ctypes.Structure):
    """Event from exec_events perf buffer"""

    _pack_ = 1
    _fields_ = [
        ("comm", ctypes.c_char * 16),
        ("pcomm", ctypes.c_char * 16),
        ("ino", ctypes.c_uint64),
        ("pino", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("dev", ctypes.c_uint32),
        ("pdev", ctypes.c_uint32),
    ]


class SendRecvEvent(ctypes.Structure):
    """Event from sendmsg_events/recvmsg_events perf buffers (IPv4)"""

    _pack_ = 1
    _fields_ = [
        ("comm", ctypes.c_char * 16),
        ("pcomm", ctypes.c_char * 16),
        ("ino", ctypes.c_uint64),
        ("pino", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("dev", ctypes.c_uint32),
        ("pdev", ctypes.c_uint32),
        ("bytes", ctypes.c_uint32),
        ("daddr", ctypes.c_uint32),
        ("saddr", ctypes.c_uint32),
        ("dport", ctypes.c_uint16),
        ("lport", ctypes.c_uint16),
    ]


class SendRecv6Event(ctypes.Structure):
    """Event from sendmsg6_events/recvmsg6_events perf buffers (IPv6)"""

    _pack_ = 1
    _fields_ = [
        ("comm", ctypes.c_char * 16),
        ("pcomm", ctypes.c_char * 16),
        ("daddr", ctypes.c_char * 16),  # 128-bit IPv6 address as bytes
        ("saddr", ctypes.c_char * 16),  # 128-bit IPv6 address as bytes
        ("ino", ctypes.c_uint64),
        ("pino", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("dev", ctypes.c_uint32),
        ("pdev", ctypes.c_uint32),
        ("bytes", ctypes.c_uint32),
        ("dport", ctypes.c_uint16),
        ("lport", ctypes.c_uint16),
    ]


class DNSEvent(ctypes.Structure):
    """Event from dns_events perf buffer"""

    _pack_ = 1
    _fields_ = [
        ("host", ctypes.c_char * 80),
        ("daddr", ctypes.c_uint32),
        ("daddr6", ctypes.c_char * 16),  # 128-bit IPv6 address as bytes
    ]


# Callback function types for perf buffers
# void (*sample_cb)(void *ctx, int cpu, void *data, __u32 size)
PERF_SAMPLE_CB = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32)
# void (*lost_cb)(void *ctx, int cpu, __u64 cnt)
PERF_LOST_CB = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_int, ctypes.c_uint64)


class LibBPF:
    """
    Low-level wrapper for libbpf shared library.
    Handles finding and loading libbpf.so and setting up ctypes function signatures.
    """

    _instance = None

    def __new__(cls):
        """Singleton pattern - only load libbpf once."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        # Try to find libbpf
        libbpf_path = ctypes.util.find_library("bpf")

        if not libbpf_path:
            # Try common paths directly
            common_paths = [
                "/usr/lib/x86_64-linux-gnu/libbpf.so.1",  # Debian/Ubuntu x86_64
                "/usr/lib/aarch64-linux-gnu/libbpf.so.1",  # Debian/Ubuntu arm64
                "/usr/lib64/libbpf.so.1",  # Fedora/RHEL x86_64
                "/usr/lib/libbpf.so.1",  # Generic
                "/lib/x86_64-linux-gnu/libbpf.so.1",  # Older Debian
                "/lib64/libbpf.so.1",  # Older Fedora
            ]
            for path in common_paths:
                if os.path.exists(path):
                    libbpf_path = path
                    break

        if not libbpf_path:
            raise RuntimeError(
                "libbpf shared library not found!\n\npicosnitch requires libbpf to load BPF programs." + _get_install_instructions() + "\nFor more information: https://github.com/libbpf/libbpf"
            )

        try:
            self.lib = ctypes.CDLL(libbpf_path)
        except OSError as e:
            raise RuntimeError(f"Failed to load libbpf from {libbpf_path}: {e}" + _get_install_instructions())

        self._setup_function_signatures()
        self._initialized = True

    def _setup_function_signatures(self):
        """Define ctypes signatures for libbpf functions we use."""

        # BPF object operations
        self.lib.bpf_object__open_file.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
        self.lib.bpf_object__open_file.restype = ctypes.c_void_p

        self.lib.bpf_object__load.argtypes = [ctypes.c_void_p]
        self.lib.bpf_object__load.restype = ctypes.c_int

        self.lib.bpf_object__close.argtypes = [ctypes.c_void_p]
        self.lib.bpf_object__close.restype = None

        self.lib.bpf_object__name.argtypes = [ctypes.c_void_p]
        self.lib.bpf_object__name.restype = ctypes.c_char_p

        # BPF program operations
        self.lib.bpf_object__find_program_by_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        self.lib.bpf_object__find_program_by_name.restype = ctypes.c_void_p

        self.lib.bpf_program__name.argtypes = [ctypes.c_void_p]
        self.lib.bpf_program__name.restype = ctypes.c_char_p

        self.lib.bpf_program__fd.argtypes = [ctypes.c_void_p]
        self.lib.bpf_program__fd.restype = ctypes.c_int

        # Program attachment - generic auto-attach (for fentry/fexit/tracepoint)
        self.lib.bpf_program__attach.argtypes = [ctypes.c_void_p]
        self.lib.bpf_program__attach.restype = ctypes.c_void_p

        # kprobe attachment
        self.lib.bpf_program__attach_kprobe.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_char_p]
        self.lib.bpf_program__attach_kprobe.restype = ctypes.c_void_p

        # uprobe attachment - we use the opts version for symbol resolution
        self.lib.bpf_program__attach_uprobe_opts.argtypes = [
            ctypes.c_void_p,  # prog
            ctypes.c_int,  # pid (-1 for all)
            ctypes.c_char_p,  # binary_path
            ctypes.c_size_t,  # func_offset (0 when using func_name in opts)
            ctypes.c_void_p,  # opts (bpf_uprobe_opts*)
        ]
        self.lib.bpf_program__attach_uprobe_opts.restype = ctypes.c_void_p

        # Link operations
        self.lib.bpf_link__destroy.argtypes = [ctypes.c_void_p]
        self.lib.bpf_link__destroy.restype = ctypes.c_int

        # BPF map operations
        self.lib.bpf_object__find_map_by_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        self.lib.bpf_object__find_map_by_name.restype = ctypes.c_void_p

        self.lib.bpf_map__fd.argtypes = [ctypes.c_void_p]
        self.lib.bpf_map__fd.restype = ctypes.c_int

        # Perf buffer operations
        self.lib.perf_buffer__new.argtypes = [
            ctypes.c_int,  # map_fd
            ctypes.c_size_t,  # page_cnt
            ctypes.c_void_p,  # sample_cb
            ctypes.c_void_p,  # lost_cb
            ctypes.c_void_p,  # ctx
            ctypes.c_void_p,  # opts
        ]
        self.lib.perf_buffer__new.restype = ctypes.c_void_p

        self.lib.perf_buffer__poll.argtypes = [ctypes.c_void_p, ctypes.c_int]
        self.lib.perf_buffer__poll.restype = ctypes.c_int

        self.lib.perf_buffer__free.argtypes = [ctypes.c_void_p]
        self.lib.perf_buffer__free.restype = None

        # Error handling
        self.lib.libbpf_strerror.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t]
        self.lib.libbpf_strerror.restype = ctypes.c_int


# Structure for bpf_uprobe_opts - must match libbpf's definition
class BpfUprobeOpts(ctypes.Structure):
    """libbpf bpf_uprobe_opts structure for uprobe attachment with symbol name."""

    _fields_ = [
        ("sz", ctypes.c_size_t),  # size of this struct for versioning
        ("ref_ctr_offset", ctypes.c_size_t),
        ("bpf_cookie", ctypes.c_uint64),
        ("retprobe", ctypes.c_bool),  # is this a return probe?
        ("func_name", ctypes.c_char_p),  # function name to attach to
        ("attach_mode", ctypes.c_int),  # enum probe_attach_mode
    ]


class BPFMap:
    """
    Wrapper for a BPF map providing BCC-like interface.
    Handles perf buffer setup and event parsing.
    """

    def __init__(self, bpf_obj: "BPFObject", name: str):
        self.bpf_obj = bpf_obj
        self.name = name
        self._event_type = self._determine_event_type(name)

    @staticmethod
    def _determine_event_type(name: str):
        """Determine the event structure type based on map name."""
        if "exec_events" in name:
            return ExecEvent
        elif "sendmsg6_events" in name or "recvmsg6_events" in name:
            return SendRecv6Event
        elif "sendmsg_events" in name or "recvmsg_events" in name:
            return SendRecvEvent
        elif "dns_events" in name:
            return DNSEvent
        return None

    def open_perf_buffer(self, callback: Callable, lost_cb: Optional[Callable] = None, page_cnt: int = 64):
        """
        Open a perf buffer for this map with BCC-style API.

        Args:
            callback: Function called for each event (cpu, data, size)
            lost_cb: Optional function called when events are lost (cpu, count)
            page_cnt: Number of pages for the ring buffer (must be power of 2)
        """
        self.bpf_obj._open_perf_buffer(self.name, callback, lost_cb, page_cnt)

    def event(self, data_ptr):
        """
        Parse raw event data into the appropriate structure.

        Args:
            data_ptr: Pointer to raw event data from perf buffer callback

        Returns:
            Parsed event structure (ExecEvent, SendRecvEvent, etc.)
        """
        if self._event_type:
            return ctypes.cast(data_ptr, ctypes.POINTER(self._event_type)).contents
        return data_ptr


class BPFObject:
    """
    High-level wrapper for BPF object operations.
    Manages the lifecycle of a loaded BPF program including maps and perf buffers.
    """

    def __init__(self, obj_path: str):
        self.libbpf = LibBPF()
        self.obj_path = obj_path
        self.obj = None
        self._programs: Dict[str, ctypes.c_void_p] = {}
        self._maps: Dict[str, ctypes.c_void_p] = {}
        self._map_fds: Dict[str, int] = {}
        self._links = []
        self._perf_buffers = []
        self._callbacks = []  # Must keep references to prevent garbage collection

    def load(self) -> "BPFObject":
        """Load the BPF object file into the kernel."""
        if not os.path.exists(self.obj_path):
            raise FileNotFoundError(f"BPF object file not found: {self.obj_path}")

        # Open object file
        self.obj = self.libbpf.lib.bpf_object__open_file(self.obj_path.encode(), None)
        if not self.obj:
            err = ctypes.get_errno()
            raise RuntimeError(f"Failed to open BPF object {self.obj_path}: {os.strerror(err) if err else 'unknown error'}")

        # Load into kernel
        ret = self.libbpf.lib.bpf_object__load(self.obj)
        if ret != 0:
            self.libbpf.lib.bpf_object__close(self.obj)
            self.obj = None
            raise RuntimeError(f"Failed to load BPF object into kernel (error {ret}). Check dmesg for verifier errors. Ensure kernel has BTF support (5.8+).")

        return self

    def get_program(self, name: str) -> ctypes.c_void_p:
        """Get a BPF program by name."""
        if name not in self._programs:
            prog = self.libbpf.lib.bpf_object__find_program_by_name(self.obj, name.encode())
            if not prog:
                raise RuntimeError(f"BPF program '{name}' not found in object")
            self._programs[name] = prog
        return self._programs[name]

    def get_map(self, name: str) -> ctypes.c_void_p:
        """Get a BPF map by name."""
        if name not in self._maps:
            map_obj = self.libbpf.lib.bpf_object__find_map_by_name(self.obj, name.encode())
            if not map_obj:
                raise RuntimeError(f"BPF map '{name}' not found in object")
            self._maps[name] = map_obj
            self._map_fds[name] = self.libbpf.lib.bpf_map__fd(map_obj)
        return self._maps[name]

    def get_map_fd(self, name: str) -> int:
        """Get the file descriptor for a BPF map."""
        if name not in self._map_fds:
            self.get_map(name)
        return self._map_fds[name]

    def attach_kprobe(self, prog_name: str, retprobe: bool, fn_name: str):
        """Attach a kprobe/kretprobe program."""
        prog = self.get_program(prog_name)
        link = self.libbpf.lib.bpf_program__attach_kprobe(prog, retprobe, fn_name.encode())
        if not link:
            probe_type = "kretprobe" if retprobe else "kprobe"
            raise RuntimeError(f"Failed to attach {probe_type} to {fn_name}")
        self._links.append(link)
        return link

    def attach_uprobe(self, prog_name: str, retprobe: bool, binary_path: str, func_name: str, pid: int = -1):
        """Attach a uprobe/uretprobe program using symbol name."""
        prog = self.get_program(prog_name)

        # Set up uprobe options with function name
        opts = BpfUprobeOpts()
        opts.sz = ctypes.sizeof(BpfUprobeOpts)
        opts.ref_ctr_offset = 0
        opts.bpf_cookie = 0
        opts.retprobe = retprobe
        opts.func_name = func_name.encode()
        opts.attach_mode = 0

        link = self.libbpf.lib.bpf_program__attach_uprobe_opts(
            prog,
            pid,
            binary_path.encode(),
            0,  # offset is 0 when using func_name
            ctypes.byref(opts),
        )

        if not link:
            probe_type = "uretprobe" if retprobe else "uprobe"
            raise RuntimeError(f"Failed to attach {probe_type} to {func_name} in {binary_path}")
        self._links.append(link)
        return link

    def attach_trace(self, prog_name: str):
        """
        Auto-attach a tracing program (fentry/fexit/tracepoint).
        The program type and attachment point are determined by SEC() in the BPF code.
        """
        prog = self.get_program(prog_name)
        link = self.libbpf.lib.bpf_program__attach(prog)
        if not link:
            raise RuntimeError(f"Failed to auto-attach program {prog_name}")
        self._links.append(link)
        return link

    def _open_perf_buffer(self, map_name: str, callback: Callable, lost_callback: Optional[Callable], page_cnt: int):
        """Internal: Open a perf buffer for a map."""
        map_fd = self.get_map_fd(map_name)

        # Create C callback wrappers that call Python functions
        def sample_cb_wrapper(ctx, cpu, data, size):
            try:
                callback(cpu, data, size)
            except Exception:
                pass  # Don't let exceptions propagate to C

        def lost_cb_wrapper(ctx, cpu, cnt):
            if lost_callback:
                try:
                    lost_callback(cpu, cnt)
                except Exception:
                    pass

        # Create ctypes callback objects
        sample_cb = PERF_SAMPLE_CB(sample_cb_wrapper)
        lost_cb = PERF_LOST_CB(lost_cb_wrapper) if lost_callback else None

        # Must keep references to prevent garbage collection
        self._callbacks.append((sample_cb, lost_cb, sample_cb_wrapper, lost_cb_wrapper))

        pb = self.libbpf.lib.perf_buffer__new(
            map_fd,
            page_cnt,
            sample_cb,
            lost_cb,
            None,  # ctx
            None,  # opts
        )

        if not pb:
            raise RuntimeError(f"Failed to create perf buffer for map {map_name}")

        self._perf_buffers.append(pb)
        return pb

    def poll_perf_buffers(self, timeout_ms: int = 100) -> int:
        """Poll all perf buffers for events."""
        total = 0
        for pb in self._perf_buffers:
            ret = self.libbpf.lib.perf_buffer__poll(pb, timeout_ms)
            if ret < 0:
                if ret == -errno.EINTR:
                    continue  # Interrupted, not an error
                return ret
            total += ret
        return total

    def cleanup(self):
        """Clean up all BPF resources."""
        # Free perf buffers first
        for pb in self._perf_buffers:
            try:
                self.libbpf.lib.perf_buffer__free(pb)
            except Exception:
                pass
        self._perf_buffers.clear()
        self._callbacks.clear()

        # Destroy links
        for link in self._links:
            try:
                self.libbpf.lib.bpf_link__destroy(link)
            except Exception:
                pass
        self._links.clear()

        # Close object
        if self.obj:
            try:
                self.libbpf.lib.bpf_object__close(self.obj)
            except Exception:
                pass
            self.obj = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
        return False

    def __getitem__(self, name: str) -> BPFMap:
        """BCC-style map access: bpf_obj["map_name"]"""
        return BPFMap(self, name)


class BPF:
    """
    Main BPF class providing a BCC-compatible API.
    This is the primary interface for picosnitch to interact with BPF.
    """

    def __init__(self, src_file: Optional[str] = None, text: Optional[str] = None, obj_file: Optional[str] = None):
        """
        Initialize and load a BPF program.

        Args:
            src_file: Not supported (BCC compatibility) - must use pre-compiled
            text: Not supported (BCC compatibility) - must use pre-compiled
            obj_file: Path to compiled .bpf.o file (required)
        """
        if text is not None or src_file is not None:
            raise RuntimeError("Runtime BPF compilation not supported. Use obj_file= with a pre-compiled .bpf.o file.")

        if obj_file is None:
            raise RuntimeError("obj_file parameter is required")

        self.obj_file = obj_file
        self.bpf_obj = BPFObject(obj_file)
        self.bpf_obj.load()

    def attach_kprobe(self, event: str, fn_name: str):
        """Attach a kprobe to a kernel function."""
        self.bpf_obj.attach_kprobe(fn_name, False, event)

    def attach_kretprobe(self, event: str, fn_name: str):
        """Attach a kretprobe to a kernel function."""
        self.bpf_obj.attach_kprobe(fn_name, True, event)

    def attach_uprobe(self, name: str, sym: str, fn_name: str, pid: int = -1):
        """Attach a uprobe to a userspace function."""
        binary_path = self._resolve_library(name)
        self.bpf_obj.attach_uprobe(fn_name, False, binary_path, sym, pid)

    def attach_uretprobe(self, name: str, sym: str, fn_name: str, pid: int = -1):
        """Attach a uretprobe to a userspace function."""
        binary_path = self._resolve_library(name)
        self.bpf_obj.attach_uprobe(fn_name, True, binary_path, sym, pid)

    @staticmethod
    def _resolve_library(name: str) -> str:
        """Resolve a library name to its full path."""
        if name == "c":
            # Find libc
            libc_path = ctypes.util.find_library("c")
            if not libc_path:
                # Try common paths
                for path in ["/lib/x86_64-linux-gnu/libc.so.6", "/lib/aarch64-linux-gnu/libc.so.6", "/lib64/libc.so.6"]:
                    if os.path.exists(path):
                        return path
                raise RuntimeError("libc not found")
            # find_library returns just the name, need full path
            if not libc_path.startswith("/"):
                # Try to find the full path
                try:
                    result = subprocess.run(["ldconfig", "-p"], capture_output=True, text=True, check=True)
                    for line in result.stdout.splitlines():
                        if "libc.so.6" in line and "=>" in line:
                            return line.split("=>")[1].strip()
                except Exception:
                    pass
                # Fallback to common paths
                for path in ["/lib/x86_64-linux-gnu/libc.so.6", "/lib/aarch64-linux-gnu/libc.so.6", "/lib64/libc.so.6"]:
                    if os.path.exists(path):
                        return path
            return libc_path
        return name

    def __getitem__(self, key: str) -> BPFMap:
        """Map access: b["map_name"]"""
        return self.bpf_obj[key]

    def perf_buffer_poll(self, timeout: int = 100) -> int:
        """Poll all perf buffers for events."""
        return self.bpf_obj.poll_perf_buffers(timeout)

    def cleanup(self):
        """Clean up all BPF resources."""
        self.bpf_obj.cleanup()

    @staticmethod
    def get_syscall_fnname(syscall: str) -> str:
        """
        Get the kernel function name for a syscall.
        Handles different naming conventions across kernel versions/architectures.
        """
        arch = platform.machine()

        # Check /proc/kallsyms for the actual function name
        prefixes = []
        if arch == "x86_64":
            prefixes = ["__x64_sys_", "__se_sys_", "sys_"]
        elif arch == "aarch64":
            prefixes = ["__arm64_sys_", "__se_sys_", "sys_"]
        else:
            prefixes = ["sys_"]

        try:
            with open("/proc/kallsyms", "r") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 3:
                        symbol = parts[2]
                        for prefix in prefixes:
                            if symbol == f"{prefix}{syscall}":
                                return symbol
        except Exception:
            pass

        # Fallback to most common pattern
        if arch == "x86_64":
            return f"__x64_sys_{syscall}"
        elif arch == "aarch64":
            return f"__arm64_sys_{syscall}"
        return f"sys_{syscall}"

    @staticmethod
    def support_kfunc() -> bool:
        """Check if kernel supports kfunc/fentry/fexit (requires 5.5+)."""
        try:
            with open("/proc/version", "r") as f:
                version_str = f.read()
            # Extract kernel version
            match = re.search(r"Linux version (\d+)\.(\d+)", version_str)
            if match:
                major, minor = int(match.group(1)), int(match.group(2))
                return (major, minor) >= (5, 5)
        except Exception:
            pass
        # Assume modern kernel if we can't determine
        return True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
        return False
