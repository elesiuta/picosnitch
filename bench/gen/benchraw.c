/* benchraw: raw IP socket egress with a custom protocol number.
 *
 * socket(AF_INET, SOCK_RAW, proto) sends via inet_sendmsg -> raw_sendmsg, so a
 * monitor hooking that path sees it, but tools that only parse /proc/net/{tcp,udp}
 * or match TCP/UDP on the wire do not attribute it.
 * Egress only (the peer has no listener for the custom proto).
 *
 * usage: benchraw -H <peer> -b <total_bytes> [-p <ip_proto>] [-s <chunk>] [-r <bytes_per_sec>]
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
#include <time.h>
#include <unistd.h>

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

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    const char *host = "10.99.0.2";
    uint64_t total = 4ull << 20;
    uint64_t rate = 0;
    int proto = 253, chunk = 1400, opt;   /* 253/254 = RFC3692 experimentation */
    while ((opt = getopt(argc, argv, "H:b:p:s:r:")) != -1) {
        switch (opt) {
        case 'H': host = optarg; break;
        case 'b': total = strtoull(optarg, NULL, 10); break;
        case 'p': proto = atoi(optarg); break;
        case 's': chunk = atoi(optarg); break;
        case 'r': rate = strtoull(optarg, NULL, 10); break;
        default: return 2;
        }
    }
    int fd = socket(AF_INET, SOCK_RAW, proto);
    if (fd < 0) { perror("raw socket (needs CAP_NET_RAW)"); return 1; }
    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    inet_pton(AF_INET, host, &dst.sin_addr);
    uint8_t *buf = malloc(chunk);
    memset(buf, 0x6B, chunk);
    uint64_t app_sent = 0;
    uint64_t start = now_ns();
    while (app_sent < total) {
        size_t want = (total - app_sent) > (uint64_t)chunk ? (size_t)chunk : (size_t)(total - app_sent);
        ssize_t w = sendto(fd, buf, want, 0, (void *)&dst, sizeof dst);
        if (w > 0) {
            app_sent += (uint64_t)w;
            pace(rate, app_sent, start);
        }
        else break;
    }
    close(fd);
    printf("RESULT app_sent=%llu app_recv=0 want=%llu proto=raw%d dir=up peer=%s lport=0 rport=0 pid=%d exe=%s\n",
           (unsigned long long)app_sent, (unsigned long long)total, proto, host, (int)getpid(), argv[0]);
    return 0;
}
