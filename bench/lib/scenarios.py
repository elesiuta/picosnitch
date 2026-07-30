"""The scenario suite. Each scenario runs traffic with a known byte volume
using a UNIQUE-PER-TRIAL executable name, and returns a GT (ground truth).

Direction is from the host's perspective: egress = upload, ingress = download.

Bulk / accuracy scenarios are PACED to a sustained rate (RATE) so the transfer
spans several seconds, which is what rate-integrating / pcap tools measure. The
scenarios that are ABOUT bursts or fast exits (s11, s20) stay unpaced on purpose.
Downloads are paced by the server (the rate travels in the wire header).
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

from harness import BIN, GT, HOST4, PEER4, PEER6, PORT_SCTP, PORT_TCP, PORT_UDP, VETH, Scenario, sh

MB = 1 << 20
RATE = 5 * MB  # 5 MiB/s ~ 40 Mbit/s: a realistic sustained rate; also keeps
# every paced transfer >5s so bandwhich's 5s-rolling-average
# cumulative gets a fair, steady-state window to measure.


def _parse_result(out, rc):
    res = {"_rc": rc, "_out": (out or "").strip()}
    for line in (out or "").splitlines():
        if line.startswith("RESULT "):
            for kv in line.split()[1:]:
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    res[k] = v
    return res


def _finalize(ctx, exe, proto, family, t0, t1, results, peer=PEER4, wire_from="peer"):
    # wire_from="loop": traffic never reaches the peer namespace, so there is no
    # wire measurement and wire-layer tools score N/A on bandwidth
    if wire_from == "peer":
        we, wep, wi, wip = ctx.netlab.read()
    else:
        we = wep = wi = wip = 0
    app_sent = sum(int(r.get("app_sent", 0)) for r in results)
    app_recv = sum(int(r.get("app_recv", 0)) for r in results)
    ok = all(r.get("_rc") == 0 for r in results) and (app_sent + app_recv) > 0
    if proto in ("tcp", "sctp"):
        # reliable transports move exactly what was asked for; a short transfer
        # means the generator failed and the trial cannot be scored
        want = sum(int(r.get("want", 0)) for r in results)
        if want and app_sent + app_recv < want * 0.99:
            ok = False
    last = results[-1] if results else {}
    return GT(
        app_sent=app_sent,
        app_recv=app_recv,
        wire_egress=we,
        wire_egress_pkts=wep,
        wire_ingress=wi,
        wire_ingress_pkts=wip,
        t0=t0,
        t1=t1,
        proto=proto,
        family=family,
        rport=int(last.get("rport", 0) or 0),
        lport=int(last.get("lport", 0) or 0),
        exe=exe,
        peer=peer,
        ok=ok,
        raw=" || ".join(r.get("_out", "") for r in results),
    )


# --- run-function builders (each derives the UNIQUE per-trial name) ---------- #
def single(base, gen, argv_fn, proto, family=2, peer=PEER4):
    def run(ctx):
        path = ctx.named_gen(gen, base)
        exe = Path(path).name
        ctx.netlab.reset()
        t0 = time.time()
        res = ctx.run_gen([path, *argv_fn(path, ctx)])
        t1 = time.time()
        return _finalize(ctx, exe, proto, family, t0, t1, [res], peer=peer)

    return run


def concurrent(base, gen, argvs, proto, family=2):
    def run(ctx):
        path = ctx.named_gen(gen, base)
        exe = Path(path).name
        ctx.netlab.reset()
        t0 = time.time()
        procs = [subprocess.Popen(ctx.gen_cmd([path, *a]), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) for a in argvs]
        outs = []
        for p in procs:
            try:
                o, _ = p.communicate(timeout=180)
            except subprocess.TimeoutExpired:
                p.kill()
                o = ""
            outs.append(_parse_result(o, p.returncode))
        t1 = time.time()
        return _finalize(ctx, exe, proto, family, t0, t1, outs)

    return run


def sequential(base, gen, argv, count, proto, family=2):
    def run(ctx):
        path = ctx.named_gen(gen, base)
        exe = Path(path).name
        ctx.netlab.reset()
        t0 = time.time()
        outs = [ctx.run_gen([path, *argv]) for _ in range(count)]
        t1 = time.time()
        return _finalize(ctx, exe, proto, family, t0, t1, outs)

    return run


def loopback(base):
    def run(ctx):
        path = ctx.named_gen("benchgen", base)
        exe = Path(path).name
        t0 = time.time()
        res = ctx.run_gen([path, "-H", "127.0.0.1", "-t", "tcp", "-d", "down", "-r", str(RATE), "-b", str(24 * MB)])
        t1 = time.time()
        return _finalize(ctx, exe, "tcp", 2, t0, t1, [res], peer="127.0.0.1", wire_from="loop")

    return run


def afpacket(base):
    def run(ctx):
        path = ctx.named_gen("benchpacket", base)
        exe = Path(path).name
        mac = ctx.netlab.peer_mac()
        ctx.netlab.reset()
        t0 = time.time()
        res = ctx.run_gen([path, "-i", VETH, "-S", HOST4, "-D", PEER4, "-M", mac, "-b", str(4 * MB)])
        t1 = time.time()
        return _finalize(ctx, exe, "afpacket", 2, t0, t1, [res])

    return run


def container(base):
    def run(ctx):
        name = ctx.unique(base)
        img = "alpine:3.20"
        static = str(BIN / "benchgen_static")
        ctx.netlab.reset()
        t0 = time.time()
        sh(["docker", "rm", "-f", "benchctr"])
        r = sh(["docker", "run", "--rm", "--name", "benchctr", "-v", f"{static}:/{name}:ro", img, f"/{name}", "-H", PEER4, "-t", "tcp", "-d", "up", "-r", str(RATE), "-b", str(24 * MB)], timeout=180)
        t1 = time.time()
        res = _parse_result((r.stdout or "") + (r.stderr or ""), r.returncode)
        return _finalize(ctx, name, "tcp", 2, t0, t1, [res])

    return run


# --- the catalog ------------------------------------------------------------ #
def build_scenarios():
    S = []

    def add(sid, name, cat, dirs, proto, run, exe, **kw):
        S.append(Scenario(sid=sid, name=name, category=cat, directions=dirs, proto=proto, run=run, exe=exe, **kw))

    rate = ["-r", str(RATE)]

    # fmt: off
    # (keep the catalog compact: one add() per scenario, not one argument per line)
    # baseline / control
    add("s01", "TCP bulk download (control)", "baseline", ["ingress"], "tcp",
        single("bg_tcp_dl", "benchgen", lambda p, c: ["-H", PEER4, "-t", "tcp", "-d", "down", *rate, "-b", str(32 * MB)], "tcp"),
        "bg_tcp_dl", rport=PORT_TCP, desc="Paced bulk TCP download; the control every tool must pass.")
    add("s02", "TCP bulk upload", "baseline", ["egress"], "tcp",
        single("bg_tcp_ul", "benchgen", lambda p, c: ["-H", PEER4, "-t", "tcp", "-d", "up", *rate, "-b", str(32 * MB)], "tcp"),
        "bg_tcp_ul", rport=PORT_TCP, desc="Paced bulk TCP upload (egress accounting).")
    add("s03", "TCP full-duplex up+down", "baseline", ["egress", "ingress"], "tcp",
        concurrent("bg_tcp_duo", "benchgen",
                   [["-H", PEER4, "-t", "tcp", "-d", "up", *rate, "-b", str(24 * MB)],
                    ["-H", PEER4, "-t", "tcp", "-d", "down", *rate, "-b", str(24 * MB)]], "tcp"),
        "bg_tcp_duo", rport=PORT_TCP, desc="Simultaneous up+down; must separate tx/rx.")

    # protocol coverage
    add("s04", "UDP bulk up+down", "protocol", ["egress", "ingress"], "udp",
        concurrent("bg_udp", "benchgen",
                   [["-H", PEER4, "-t", "udp", "-d", "up", *rate, "-b", str(24 * MB)],
                    ["-H", PEER4, "-t", "udp", "-d", "down", *rate, "-b", str(24 * MB)]], "udp"),
        "bg_udp", rport=PORT_UDP, desc="UDP both directions.")
    add("s05", "ICMP echo flood w/ payload", "protocol", ["egress", "ingress"], "icmp",
        single("bg_icmp", "benchicmp", lambda p, c: ["-H", PEER4, "-b", str(6 * MB), "-s", "1000"], "icmp"),
        "bg_icmp", desc="ICMP echo w/ payload; invisible to TCP/UDP-only monitors.",
        note="ICMP is neither TCP nor UDP; monitors that only parse TCP/UDP miss it entirely.")
    add("s06", "UDP/443 bulk", "protocol", ["egress"], "udp",
        single("bg_quic", "benchgen", lambda p, c: ["-H", PEER4, "-t", "udp", "-d", "up", "-P", "443", *rate, "-b", str(24 * MB)], "udp"),
        "bg_quic", rport=443, desc="Bulk UDP egress on port 443.")
    add("s07", "IPv6 TCP transfer", "protocol", ["ingress"], "tcp",
        single("bg_tcp6", "benchgen", lambda p, c: ["-6", "-H", PEER6, "-t", "tcp", "-d", "down", *rate, "-b", str(24 * MB)], "tcp", family=10, peer=PEER6),
        "bg_tcp6", rport=PORT_TCP, family=10, peer=PEER6, desc="IPv6 download; v6 support/attribution.")
    add("s08", "SCTP transfer", "protocol", ["ingress"], "sctp",
        single("bg_sctp", "benchgen", lambda p, c: ["-H", PEER4, "-t", "sctp", "-d", "down", *rate, "-b", str(24 * MB)], "sctp"),
        "bg_sctp", rport=PORT_SCTP, desc="SCTP download; TCP/UDP-only parsers miss it.",
        note="SCTP is neither TCP nor UDP; TCP/UDP-only parsers miss it.")
    add("s09", "Small-packet UDP/53 flood", "protocol", ["egress"], "udp",
        single("bg_dns", "benchgen", lambda p, c: ["-H", PEER4, "-t", "udp", "-d", "up", "-P", "53", "-z", "64", "-r", str(2 * MB), "-b", str(4 * MB)], "udp"),
        "bg_dns", rport=53, desc="Many small UDP datagrams on port 53.")
    add("s10", "Raw IP socket (proto 253) egress", "protocol", ["egress"], "raw253",
        single("bg_rawip", "benchraw", lambda p, c: ["-H", PEER4, "-b", str(4 * MB), "-p", "253"], "raw253"),
        "bg_rawip", desc="Custom-protocol raw IP; pcap TCP/UDP parsers miss it.",
        note="raw sockets with a custom IP protocol carry no TCP/UDP header; TCP/UDP-only attribution misses them.")

    # evasion / attribution
    add("s11", "Short-lived processes", "evasion", ["egress"], "tcp",
        sequential("bg_short", "benchgen", ["-H", PEER4, "-t", "tcp", "-d", "up", "-b", str(512 * 1024)], 20, "tcp"),
        "bg_short", rport=PORT_TCP, desc="20 connect+send+exit processes; /proc-pollers bucket as unknown.",
        note="/proc-scan attribution loses processes that exit before the next scan; their traffic lands in an unknown bucket.")
    add("s12", "AF_PACKET raw-frame injection", "evasion", ["egress"], "afpacket",
        afpacket("bg_afpkt"), "bg_afpkt", rport=PORT_UDP,
        desc="Raw L2 injection bypassing the INET socket path.",
        note="AF_PACKET hands complete L2 frames to the driver, bypassing the INET socket path, so monitors "
             "hooking the INET socket functions record nothing; the writes are ordinary syscalls, so syscall "
             "tracing still sees them; pcap taps see the frames but have no /proc/net/{tcp,udp} entry to "
             "attribute them to a process.")
    add("s13", "io_uring data path", "evasion", ["egress"], "tcp",
        single("bg_uring", "benchuring", lambda p, c: ["-H", PEER4, "-d", "up", "-b", str(24 * MB)], "tcp"),
        "bg_uring", rport=PORT_TCP, desc="Upload via io_uring; kernel-fn hooks catch it, per-syscall byte counting misses it.")
    add("s14", "sendfile() zero-copy upload", "evasion", ["egress"], "tcp",
        single("bg_sendf", "benchgen", lambda p, c: ["-H", PEER4, "-t", "tcp", "-d", "up", "-m", "sendfile", *rate, "-b", str(32 * MB)], "tcp"),
        "bg_sendf", rport=PORT_TCP, desc="Zero-copy sendfile upload (post-sendpage path).")
    add("s15", "sendmmsg batched UDP", "evasion", ["egress"], "udp",
        single("bg_smmsg", "benchgen", lambda p, c: ["-H", PEER4, "-t", "udp", "-d", "up", "-m", "sendmmsg", *rate, "-b", str(24 * MB)], "udp"),
        "bg_smmsg", rport=PORT_UDP, desc="Batched sendmmsg UDP egress.")
    add("s16", "Loopback-only transfer", "evasion", ["ingress"], "tcp",
        loopback("bg_loop"), "bg_loop", rport=PORT_TCP, peer="127.0.0.1",
        desc="Transfer over lo; many tools skip loopback by default.",
        note="traffic never leaves lo, which many monitors skip by default.")
    add("s17", "In-container (docker) egress", "evasion", ["egress"], "tcp",
        container("bg_ctr"), "bg_ctr", rport=PORT_TCP,
        desc="Upload from inside a docker container; container attribution.")
    add("s18", "Low-and-slow drip upload", "evasion", ["egress"], "tcp",
        single("bg_slow", "benchgen", lambda p, c: ["-H", PEER4, "-t", "tcp", "-d", "up", "-r", str(128 * 1024), "-b", str(2 * MB)], "tcp"),
        "bg_slow", rport=PORT_TCP, desc="2 MiB at 128 KiB/s (~16s); totals must still add up.")

    # bandwidth stressors
    add("s19", "Many small TCP connections", "bandwidth", ["egress"], "tcp",
        single("bg_many", "benchgen", lambda p, c: ["-H", PEER4, "-t", "tcp", "-d", "up", "-c", "60", "-r", str(2 * MB), "-b", str(64 * 1024)], "tcp"),
        "bg_many", rport=PORT_TCP, desc="One process, 60 small paced connections; payload-vs-wire gap.")
    add("s20", "High-rate parallel burst", "bandwidth", ["egress"], "tcp",
        concurrent("bg_burst", "benchgen",
                   [["-H", PEER4, "-t", "tcp", "-d", "up", "-b", str(256 * 1024)] for _ in range(30)], "tcp"),
        "bg_burst", rport=PORT_TCP, desc="30 concurrent connections at once; accounting during a high-rate burst.")

    # ingress counterparts of the technique scenarios
    add("s21", "io_uring download (recv)", "evasion", ["ingress"], "tcp",
        single("bg_uringdl", "benchuring", lambda p, c: ["-H", PEER4, "-d", "down", "-b", str(24 * MB)], "tcp"),
        "bg_uringdl", rport=PORT_TCP,
        desc="Download via io_uring recv; recv-side syscall-bypass (per-syscall byte counting misses it, kernel-fn hooks catch it).")
    add("s22", "splice() zero-copy download", "evasion", ["ingress"], "tcp",
        single("bg_splice", "benchgen", lambda p, c: ["-H", PEER4, "-t", "tcp", "-d", "down", "-m", "splice", *rate, "-b", str(32 * MB)], "tcp"),
        "bg_splice", rport=PORT_TCP,
        desc="Zero-copy splice() download (tcp_splice_read path); the recv counterpart of sendfile (s14).")
    add("s23", "recvmmsg batched UDP (recv)", "evasion", ["ingress"], "udp",
        single("bg_rmmsg", "benchgen", lambda p, c: ["-H", PEER4, "-t", "udp", "-d", "down", "-m", "recvmmsg", *rate, "-b", str(24 * MB)], "udp"),
        "bg_rmmsg", rport=PORT_UDP,
        desc="Batched recvmmsg UDP ingress; the recv counterpart of sendmmsg (s15).")
    add("s24", "IPv6 UDP download", "protocol", ["ingress"], "udp",
        single("bg_udp6", "benchgen", lambda p, c: ["-6", "-H", PEER6, "-t", "udp", "-d", "down", *rate, "-b", str(24 * MB)], "udp", family=10, peer=PEER6),
        "bg_udp6", rport=PORT_UDP, family=10, peer=PEER6, desc="IPv6 UDP download; fills the IPv6 x UDP gap.")
    # fmt: on
    return S
