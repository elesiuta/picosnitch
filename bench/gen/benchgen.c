/* benchgen — versatile traffic generator (client side) for the benchmark.
 *
 * Transfers a requested number of application-layer bytes to/from benchserver
 * over TCP, UDP, or SCTP, using a selectable send method, optional rate pacing,
 * an optional port override, and an optional repeat count (fresh connection each
 * iteration — used for the many-small-connections scenarios). Prints one
 * machine-readable RESULT line with the actual app-layer bytes sent/received.
 *
 * The binary is installed under a UNIQUE per-scenario name (the harness copies
 * it) so each monitor's per-process attribution can be checked by name.
 *
 * usage: benchgen -H <peer> -t tcp|udp|sctp -d up|down -b <bytes>
 *                 [-m plain|sendmmsg|sendfile|recvmmsg|splice] [-r <bytes_per_sec>]
 *                 [-P <port>] [-z <udp_datagram>] [-c <nconns>, tcp/sctp only] [-6]
 *   up   = SEND <bytes> to the peer (egress);  down = RECEIVE <bytes> (ingress)
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAGIC 0x424E4348u
#define PORT_TCP 9101
#define PORT_UDP 9102
#define PORT_SCTP 9103
#define IPPROTO_SCTP_ 132
#define CHUNK (1 << 16)

struct hdr {
    uint32_t magic; uint8_t mode; uint8_t proto; uint16_t pad; uint64_t nbytes; uint64_t rate;
} __attribute__((packed));

static uint8_t buf[CHUNK];

/* config, filled from argv */
static struct {
    const char *host, *proto, *dir, *method;
    uint64_t nbytes, rate;
    int v6, port, dgsize;
} C;

static uint64_t now_ns(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}
static void pace(uint64_t rate, uint64_t sent, uint64_t start_ns) {
    if (!rate) return;
    uint64_t target = start_ns + (sent * 1000000000ull) / rate, cur = now_ns();
    if (target > cur) {
        struct timespec ts = {(target - cur) / 1000000000ull, (target - cur) % 1000000000ull};
        nanosleep(&ts, NULL);
    }
}

/* one connection/transfer; accumulates egress/ingress bytes; records ports */
static int do_transfer(uint64_t *psent, uint64_t *precv, int *lport, int *rport) {
    int is_udp = strcmp(C.proto, "udp") == 0, is_sctp = strcmp(C.proto, "sctp") == 0;
    int is_up = strcmp(C.dir, "up") == 0;
    int family = C.v6 ? AF_INET6 : AF_INET;
    int fd = socket(family, is_udp ? SOCK_DGRAM : SOCK_STREAM, is_sctp ? IPPROTO_SCTP_ : 0);
    if (fd < 0) { perror("socket"); return 1; }
    int b = 8 << 20;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &b, sizeof b);
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &b, sizeof b);

    struct sockaddr_storage ss; socklen_t slen;
    memset(&ss, 0, sizeof ss);
    if (family == AF_INET) {
        struct sockaddr_in *a = (void *)&ss;
        a->sin_family = AF_INET; a->sin_port = htons(C.port); inet_pton(AF_INET, C.host, &a->sin_addr);
        slen = sizeof *a;
    } else {
        struct sockaddr_in6 *a = (void *)&ss;
        a->sin6_family = AF_INET6; a->sin6_port = htons(C.port); inet_pton(AF_INET6, C.host, &a->sin6_addr);
        slen = sizeof *a;
    }
    if (is_udp) { struct timeval tv = {2, 0}; setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv); }
    else if (connect(fd, (void *)&ss, slen) < 0) { perror("connect"); close(fd); return 1; }

    struct hdr h = {.magic = htonl(MAGIC), .mode = is_up ? 0 : 1,
                    .proto = (uint8_t)(is_udp ? 17 : is_sctp ? 132 : 6), .pad = 0,
                    .nbytes = htobe64(C.nbytes), .rate = htobe64(C.rate)};
    uint64_t start = now_ns();
    uint64_t base = *psent;    /* pace on THIS connection's bytes, not the cumulative */
#define PACED (*psent - base)

    if (is_udp) {
        if (sendto(fd, &h, sizeof h, 0, (void *)&ss, slen) > 0) *psent += sizeof h;
        int dg = C.dgsize;
        if (is_up) {
            memset(buf, 0x5A, CHUNK);
            if (strcmp(C.method, "sendmmsg") == 0) {
                enum { BATCH = 32 };
                struct mmsghdr m[BATCH]; struct iovec iov[BATCH];
                for (int i = 0; i < BATCH; i++) {
                    iov[i].iov_base = buf; iov[i].iov_len = dg;
                    memset(&m[i], 0, sizeof m[i]);
                    m[i].msg_hdr.msg_iov = &iov[i]; m[i].msg_hdr.msg_iovlen = 1;
                    m[i].msg_hdr.msg_name = &ss; m[i].msg_hdr.msg_namelen = slen;
                }
                while (*psent < C.nbytes + sizeof h) {
                    int n = sendmmsg(fd, m, BATCH, 0);
                    if (n <= 0) break;
                    for (int i = 0; i < n; i++) *psent += m[i].msg_len;
                    pace(C.rate, PACED, start);
                }
            } else {
                while (*psent < C.nbytes + sizeof h) {
                    ssize_t w = sendto(fd, buf, dg, 0, (void *)&ss, slen);
                    if (w <= 0) break;
                    *psent += (uint64_t)w;
                    pace(C.rate, PACED, start);
                }
            }
        } else if (strcmp(C.method, "recvmmsg") == 0) {
            /* batched receive: one syscall drains up to BATCH datagrams. tools
             * that count per-recv-syscall undercount; hooks at inet_recvmsg see
             * each datagram. datagrams are <= 2048 here (default dgsize 1400). */
            enum { BATCH = 32 };
            static uint8_t rbuf[BATCH][2048];
            struct mmsghdr m[BATCH]; struct iovec iov[BATCH];
            for (int i = 0; i < BATCH; i++) {
                iov[i].iov_base = rbuf[i]; iov[i].iov_len = sizeof rbuf[i];
                memset(&m[i], 0, sizeof m[i]);
                m[i].msg_hdr.msg_iov = &iov[i]; m[i].msg_hdr.msg_iovlen = 1;
            }
            while (*precv < C.nbytes) {
                int n = recvmmsg(fd, m, BATCH, MSG_WAITFORONE, NULL);
                if (n <= 0) break;
                for (int i = 0; i < n; i++) *precv += m[i].msg_len;
            }
        } else {
            while (*precv < C.nbytes) {
                ssize_t r = recvfrom(fd, buf, CHUNK, 0, NULL, NULL);
                if (r <= 0) break;
                *precv += (uint64_t)r;
            }
        }
    } else {
        if (send(fd, &h, sizeof h, 0) > 0) *psent += sizeof h;
        if (is_up) {
            if (strcmp(C.method, "sendfile") == 0) {
                char tmpl[] = "/tmp/benchgen.XXXXXX";
                int tf = mkstemp(tmpl); unlink(tmpl);
                memset(buf, 0x33, CHUNK);
                for (uint64_t w = 0; w < C.nbytes; w += CHUNK) if (write(tf, buf, CHUNK) < 0) break;
                lseek(tf, 0, SEEK_SET);
                off_t off = 0; uint64_t left = C.nbytes;
                while (left > 0) {
                    ssize_t s = sendfile(fd, tf, &off, left > CHUNK ? CHUNK : left);
                    if (s <= 0) break;
                    *psent += (uint64_t)s; left -= (uint64_t)s; pace(C.rate, PACED, start);
                }
                close(tf);
            } else {
                memset(buf, 0x33, CHUNK);
                uint64_t left = C.nbytes;
                while (left > 0) {
                    size_t want = left > CHUNK ? CHUNK : (size_t)left;
                    ssize_t s = send(fd, buf, want, 0);
                    if (s <= 0) break;
                    *psent += (uint64_t)s; left -= (uint64_t)s; pace(C.rate, PACED, start);
                }
            }
        } else if (strcmp(C.method, "splice") == 0) {
            /* zero-copy receive: splice(socket -> pipe) drives the kernel's
             * tcp_splice_read path, bypassing recvmsg. drain the pipe so it
             * can't fill and stall the transfer. */
            int pfd[2];
            if (pipe(pfd) == 0) {
                uint64_t left = C.nbytes;
                while (left > 0) {
                    size_t want = left > CHUNK ? CHUNK : (size_t)left;
                    ssize_t s = splice(fd, NULL, pfd[1], NULL, want, SPLICE_F_MOVE | SPLICE_F_MORE);
                    if (s <= 0) break;
                    ssize_t drained = 0;
                    while (drained < s) {
                        ssize_t d = read(pfd[0], buf, (size_t)(s - drained) > CHUNK ? CHUNK : (size_t)(s - drained));
                        if (d <= 0) break;
                        drained += d;
                    }
                    *precv += (uint64_t)s; left -= (uint64_t)s;
                }
                close(pfd[0]); close(pfd[1]);
            }
        } else {
            uint64_t left = C.nbytes;
            while (left > 0) {
                size_t want = left > CHUNK ? CHUNK : (size_t)left;
                ssize_t r = recv(fd, buf, want, 0);
                if (r <= 0) break;
                *precv += (uint64_t)r; left -= (uint64_t)r;
            }
        }
    }
    struct sockaddr_storage la; socklen_t ll = sizeof la;
    if (getsockname(fd, (void *)&la, &ll) == 0)
        *lport = ntohs(family == AF_INET ? ((struct sockaddr_in *)&la)->sin_port
                                         : ((struct sockaddr_in6 *)&la)->sin6_port);
    *rport = C.port;
    close(fd);
    return 0;
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    C.host = "10.99.0.2"; C.proto = "tcp"; C.dir = "down"; C.method = "plain";
    C.nbytes = 10ull << 20; C.rate = 0; C.v6 = 0; C.port = 0; C.dgsize = 1400;
    int nconns = 1, opt;
    while ((opt = getopt(argc, argv, "H:t:d:b:m:r:P:z:c:6")) != -1) {
        switch (opt) {
        case 'H': C.host = optarg; break;
        case 't': C.proto = optarg; break;
        case 'd': C.dir = optarg; break;
        case 'b': C.nbytes = strtoull(optarg, NULL, 10); break;
        case 'm': C.method = optarg; break;
        case 'r': C.rate = strtoull(optarg, NULL, 10); break;
        case 'P': C.port = atoi(optarg); break;
        case 'z': C.dgsize = atoi(optarg); break;
        case 'c': nconns = atoi(optarg); break;
        case '6': C.v6 = 1; break;
        default: fprintf(stderr, "bad args\n"); return 2;
        }
    }
    if (!C.port)
        C.port = strcmp(C.proto, "udp") == 0 ? PORT_UDP
                 : strcmp(C.proto, "sctp") == 0 ? PORT_SCTP : PORT_TCP;
    /* UDP loops bound the CUMULATIVE count against a per-connection target,
     * so repeats would skip the payload; only the stream paths use -c */
    if (nconns > 1 && strcmp(C.proto, "udp") == 0) {
        fprintf(stderr, "-c > 1 is not supported with udp\n");
        return 2;
    }

    uint64_t app_sent = 0, app_recv = 0;
    int lport = 0, rport = C.port;
    for (int i = 0; i < nconns; i++)
        do_transfer(&app_sent, &app_recv, &lport, &rport);

    /* want = bytes requested, so the harness can tell a short reliable transfer
       (a failed run) from a monitor that under-reports */
    printf("RESULT app_sent=%llu app_recv=%llu want=%llu proto=%s dir=%s peer=%s lport=%d rport=%d pid=%d exe=%s\n",
           (unsigned long long)app_sent, (unsigned long long)app_recv,
           (unsigned long long)C.nbytes * (unsigned long long)nconns, C.proto, C.dir, C.host,
           lport, rport, (int)getpid(), argv[0]);
    return 0;
}
