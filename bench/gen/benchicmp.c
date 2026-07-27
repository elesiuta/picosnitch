/* benchicmp — ICMP echo traffic with a known payload volume.
 *
 * Sends N echo requests (payload P) to the peer; the peer kernel echoes them
 * back, exercising BOTH egress (requests) and ingress (replies). Uses a raw
 * ICMP socket (CAP_NET_RAW), whose send goes through inet_sendmsg -> raw_sendmsg
 * (visible to socket-layer monitors). pcap tools that parse only TCP/UDP do not
 * account ICMP.
 *
 * usage: benchicmp -H <peer> -b <total_payload_bytes> [-s <payload_per_pkt>]
 * app_sent = ICMP message bytes sent (8 hdr + payload).
 * app_recv = bytes received (raw sockets deliver IP header + ICMP reply).
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static uint16_t icsum(const void *d, int len) {
    uint32_t s = 0; const uint16_t *p = d;
    while (len > 1) { s += *p++; len -= 2; }
    if (len) s += *(const uint8_t *)p;
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return (uint16_t)~s;
}

/* A raw ICMP socket receives ALL inbound ICMP, so count only echo replies that
 * carry our id — otherwise a stray ICMP (error, other pinger) would inflate the
 * ingress count. rb is the full IP packet the raw socket delivered. */
static int is_our_reply(const uint8_t *rb, ssize_t r, uint16_t id) {
    if (r < (ssize_t)sizeof(struct iphdr)) return 0;
    const struct iphdr *ip = (const void *)rb;
    unsigned hl = (unsigned)ip->ihl * 4;
    if (hl < sizeof(struct iphdr) || r < (ssize_t)(hl + sizeof(struct icmphdr))) return 0;
    const struct icmphdr *ic = (const void *)(rb + hl);
    return ic->type == ICMP_ECHOREPLY && ntohs(ic->un.echo.id) == id;
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    const char *host = "10.99.0.2";
    uint64_t total = 4ull << 20;
    int psize = 1000, opt;
    while ((opt = getopt(argc, argv, "H:b:s:")) != -1) {
        switch (opt) {
        case 'H': host = optarg; break;
        case 'b': total = strtoull(optarg, NULL, 10); break;
        case 's': psize = atoi(optarg); break;
        default: return 2;
        }
    }
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd < 0) { perror("raw icmp socket (needs CAP_NET_RAW)"); return 1; }
    struct timeval tv = {2, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    int rcvbuf = 8 << 20;   /* absorb the reply burst so ingress isn't buffer-dropped */
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof rcvbuf);
    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    inet_pton(AF_INET, host, &dst.sin_addr);

    int msgsize = (int)sizeof(struct icmphdr) + psize;
    uint8_t *pkt = calloc(1, msgsize);
    struct icmphdr *ic = (void *)pkt;
    uint16_t id = (uint16_t)getpid();
    memset(pkt + sizeof *ic, 0x7E, psize);

    uint64_t nmsgs = (total + psize - 1) / psize;
    uint64_t app_sent = 0, app_recv = 0, nrecv = 0;
    for (uint64_t i = 0; i < nmsgs; i++) {
        ic->type = ICMP_ECHO; ic->code = 0;
        ic->un.echo.id = htons(id);
        ic->un.echo.sequence = htons((uint16_t)i);
        ic->checksum = 0;
        ic->checksum = icsum(pkt, msgsize);
        ssize_t w = sendto(fd, pkt, msgsize, 0, (void *)&dst, sizeof dst);
        if (w > 0) app_sent += (uint64_t)w;
        uint8_t rb[2048];
        ssize_t r = recv(fd, rb, sizeof rb, MSG_DONTWAIT);
        if (r > 0 && is_our_reply(rb, r, id)) { app_recv += (uint64_t)r; nrecv++; }
    }
    /* Drain the remaining replies by COUNT (not a byte threshold — replies carry a
     * 20-byte IP header the requests don't, so a byte threshold stops early and
     * leaves real ingress uncounted). Stops when every echo is back or recv times out. */
    while (nrecv < nmsgs) {
        uint8_t rb[2048];
        ssize_t r = recv(fd, rb, sizeof rb, 0);
        if (r <= 0) break;
        if (is_our_reply(rb, r, id)) { app_recv += (uint64_t)r; nrecv++; }
    }
    struct sockaddr_in la; socklen_t ll = sizeof la; int lport = 0;
    if (getsockname(fd, (void *)&la, &ll) == 0) lport = ntohs(la.sin_port);
    close(fd);
    printf("RESULT app_sent=%llu app_recv=%llu proto=icmp dir=both peer=%s lport=%d rport=0 pid=%d exe=%s\n",
           (unsigned long long)app_sent, (unsigned long long)app_recv, host, lport, (int)getpid(), argv[0]);
    return 0;
}
