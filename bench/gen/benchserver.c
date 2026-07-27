/* benchserver — controlled peer for the picosnitch benchmark.
 *
 * Runs inside the peer network namespace. Speaks a tiny framed protocol so a
 * client (the traffic generator on the host) can push or pull a requested
 * number of application-layer bytes over TCP, UDP, or SCTP. The server is
 * stateless; measurement happens in the client's RESULT line and the nft
 * counters.
 *
 * Wire header the client sends first (all fields big-endian), 24 bytes:
 *   magic  u32  = 0x424E4348 ("BNCH")
 *   mode   u8   = 0 SINK (server reads nbytes)  | 1 SOURCE (server sends nbytes)
 *   proto  u8   = informational (6 tcp, 17 udp, 132 sctp)
 *   pad    u16
 *   nbytes u64  = bytes to transfer in the chosen direction
 *   rate   u64  = bytes/sec to pace SOURCE sends (0 = unlimited)
 *
 * TCP/SCTP: reliable, connection-oriented. One header then a stream.
 * UDP: header in the first datagram; SINK counts received payload, SOURCE emits
 *      nbytes across fixed-size datagrams. UDP is lossy by nature — the harness
 *      measures actual app + wire bytes on both ends, so loss is accounted for.
 *
 * Ports: TCP 9101, UDP 9102, SCTP 9103, plus UDP sinks on 443 and 53
 * (bound on all addresses, v4+v6).
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define MAGIC 0x424E4348u
#define PORT_TCP 9101
#define PORT_UDP 9102
#define PORT_SCTP 9103
#define IPPROTO_SCTP_ 132
#define CHUNK (1 << 16)

struct hdr {
    uint32_t magic;
    uint8_t mode;
    uint8_t proto;
    uint16_t pad;
    uint64_t nbytes;
    uint64_t rate;      /* bytes/sec the server should pace its SOURCE sends to; 0 = unlimited */
} __attribute__((packed));

static volatile sig_atomic_t stop = 0;
static void on_sig(int s) { (void)s; stop = 1; }

static uint8_t buf[CHUNK];

static uint64_t now_ns(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}
/* sleep so that `sent` bytes since `start_ns` respects `rate` bytes/sec */
static void pace(uint64_t rate, uint64_t sent, uint64_t start_ns) {
    if (!rate) return;
    uint64_t target = start_ns + (sent * 1000000000ull) / rate, cur = now_ns();
    if (target > cur) {
        struct timespec ts = {(target - cur) / 1000000000ull, (target - cur) % 1000000000ull};
        nanosleep(&ts, NULL);
    }
}

/* drain n bytes from a stream socket, content discarded; return bytes read */
static uint64_t read_n(int fd, uint64_t n) {
    uint64_t got = 0;
    while (got < n) {
        size_t want = (n - got) > CHUNK ? CHUNK : (size_t)(n - got);
        ssize_t r = recv(fd, buf, want, 0);
        if (r <= 0) break;
        got += (uint64_t)r;
    }
    return got;
}

/* read exactly n bytes into p; return 1 on success, 0 on EOF/error */
static int read_exact(int fd, void *p, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = recv(fd, (uint8_t *)p + got, n - got, 0);
        if (r <= 0) return 0;
        got += (size_t)r;
    }
    return 1;
}

/* write exactly n bytes to a stream socket, paced to `rate` B/s; return written */
static uint64_t write_n(int fd, uint64_t n, uint64_t rate) {
    memset(buf, 0xAB, CHUNK);
    uint64_t sent = 0, start = now_ns();
    while (sent < n) {
        size_t want = (n - sent) > CHUNK ? CHUNK : (size_t)(n - sent);
        ssize_t w = send(fd, buf, want, 0);
        if (w <= 0) break;
        sent += (uint64_t)w;
        pace(rate, sent, start);
    }
    return sent;
}

static void handle_stream(int fd) {
    struct hdr h;
    if (!read_exact(fd, &h, sizeof h)) return;
    if (ntohl(h.magic) != MAGIC) return;
    uint64_t n = be64toh(h.nbytes);
    if (h.mode == 0)
        read_n(fd, n);
    else
        write_n(fd, n, be64toh(h.rate));
}

static int listen_stream(int family, int proto, int port) {
    int fd = socket(family, SOCK_STREAM, proto == IPPROTO_TCP ? 0 : proto);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (family == AF_INET6)
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one);
    if (family == AF_INET) {
        struct sockaddr_in a = {0};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = INADDR_ANY;
        a.sin_port = htons(port);
        if (bind(fd, (void *)&a, sizeof a) < 0) { close(fd); return -1; }
    } else {
        struct sockaddr_in6 a = {0};
        a.sin6_family = AF_INET6;
        a.sin6_addr = in6addr_any;
        a.sin6_port = htons(port);
        if (bind(fd, (void *)&a, sizeof a) < 0) { close(fd); return -1; }
    }
    if (listen(fd, 64) < 0) { close(fd); return -1; }
    return fd;
}

static int listen_udp(int family, int port) {
    int fd = socket(family, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    int rcv = 8 << 20;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof rcv);
    if (family == AF_INET6)
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one);
    if (family == AF_INET) {
        struct sockaddr_in a = {0};
        a.sin_family = AF_INET; a.sin_addr.s_addr = INADDR_ANY; a.sin_port = htons(port);
        if (bind(fd, (void *)&a, sizeof a) < 0) { close(fd); return -1; }
    } else {
        struct sockaddr_in6 a = {0};
        a.sin6_family = AF_INET6; a.sin6_addr = in6addr_any; a.sin6_port = htons(port);
        if (bind(fd, (void *)&a, sizeof a) < 0) { close(fd); return -1; }
    }
    return fd;
}

/* SOURCE: emit n bytes as ~1400-byte datagrams to the requester, paced */
static void udp_source(int fd, struct sockaddr_storage *peer, socklen_t plen,
                       uint64_t n, uint64_t rate) {
    memset(buf, 0xCD, CHUNK);
    const size_t dg = 1400;
    uint64_t sent = 0, start = now_ns();
    while (sent < n && !stop) {
        size_t want = (n - sent) > dg ? dg : (size_t)(n - sent);
        ssize_t w = sendto(fd, buf, want, 0, (void *)peer, plen);
        if (w <= 0) { struct timespec ts = {0, 1000000}; nanosleep(&ts, NULL); continue; }
        sent += (uint64_t)w;
        pace(rate, sent, start);
    }
}

/* Service a readable UDP socket WITHOUT forking per datagram (a forked-per-
 * datagram design turns a UDP flood into a fork storm that overloads the box).
 * Drain up to a bounded number of datagrams inline, discarding SINK/data;
 * fork a sender only for the rare SOURCE (download) request. */
static void udp_service(int fd) {
    struct sockaddr_storage peer;
    socklen_t plen;
    for (int i = 0; i < 8192; i++) {
        plen = sizeof peer;
        ssize_t r = recvfrom(fd, buf, CHUNK, MSG_DONTWAIT, (void *)&peer, &plen);
        if (r <= 0) break;
        if (r >= (ssize_t)sizeof(struct hdr)) {
            struct hdr h;
            memcpy(&h, buf, sizeof h);
            if (ntohl(h.magic) == MAGIC && h.mode == 1) {
                if (fork() == 0) {
                    udp_source(fd, &peer, plen, be64toh(h.nbytes), be64toh(h.rate));
                    _exit(0);
                }
            }
        }
    }
}

int main(void) {
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);
    signal(SIGCHLD, SIG_IGN);

    int t4 = listen_stream(AF_INET, IPPROTO_TCP, PORT_TCP);
    int t6 = listen_stream(AF_INET6, IPPROTO_TCP, PORT_TCP);
    int s4 = listen_stream(AF_INET, IPPROTO_SCTP_, PORT_SCTP);   /* may be -1 if sctp absent */
    int s6 = listen_stream(AF_INET6, IPPROTO_SCTP_, PORT_SCTP);
    /* UDP sinks on the benchmark port plus 443 and 53 (small-packet scenarios) */
    int udp_ports[] = {PORT_UDP, 443, 53};
    int u4[3], u6[3];
    for (int i = 0; i < 3; i++) {
        u4[i] = listen_udp(AF_INET, udp_ports[i]);
        u6[i] = listen_udp(AF_INET6, udp_ports[i]);
    }

    fprintf(stderr, "benchserver up: tcp=%d/%d sctp=%d/%d udp9102=%d/%d udp443=%d/%d udp53=%d/%d\n",
            t4, t6, s4, s6, u4[0], u6[0], u4[1], u6[1], u4[2], u6[2]);

    int fds[] = {t4, t6, s4, s6, u4[0], u6[0], u4[1], u6[1], u4[2], u6[2]};
    while (!stop) {
        fd_set rs;
        FD_ZERO(&rs);
        int mx = -1;
        for (unsigned i = 0; i < sizeof(fds) / sizeof(fds[0]); i++)
            if (fds[i] >= 0) { FD_SET(fds[i], &rs); if (fds[i] > mx) mx = fds[i]; }
        struct timeval tv = {1, 0};
        int rv = select(mx + 1, &rs, NULL, NULL, &tv);
        if (rv <= 0) continue;
        /* stream listeners: accept then fork a handler */
        int sl[] = {t4, t6, s4, s6};
        for (unsigned i = 0; i < sizeof(sl) / sizeof(sl[0]); i++) {
            if (sl[i] >= 0 && FD_ISSET(sl[i], &rs)) {
                int c = accept(sl[i], NULL, NULL);
                if (c < 0) continue;
                if (fork() == 0) { handle_stream(c); close(c); _exit(0); }
                close(c);
            }
        }
        for (int i = 0; i < 3; i++) {
            if (u4[i] >= 0 && FD_ISSET(u4[i], &rs)) udp_service(u4[i]);
            if (u6[i] >= 0 && FD_ISSET(u6[i], &rs)) udp_service(u6[i]);
        }
    }
    return 0;
}
