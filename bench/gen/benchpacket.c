/* benchpacket — AF_PACKET raw-frame egress (bypasses the socket layer).
 *
 * Crafts complete Ethernet+IP+UDP frames and injects them with a raw AF_PACKET
 * socket. This bypasses the INET socket send path (inet_sendmsg), so a
 * socket-layer monitor does not see it. pcap-based tools that tap the device
 * still see the frames, though attribution is harder (the sender holds an
 * AF_PACKET fd, not a /proc/net/{tcp,udp} entry).
 * Egress only; frames are valid UDP to the peer.
 *
 * usage: benchpacket -i <iface> -S <srcip> -D <dstip> -M <dst_mac> -b <bytes>
 *                    [-P <dport>] [-s <payload_per_frame>]
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

static uint16_t csum16(const void *data, int len, uint32_t init) {
    uint32_t s = init;
    const uint16_t *p = data;
    while (len > 1) { s += *p++; len -= 2; }
    if (len) s += *(const uint8_t *)p;
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return (uint16_t)~s;
}
static int parse_mac(const char *s, uint8_t out[6]) {
    return sscanf(s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                  &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]) == 6 ? 0 : -1;
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    const char *iface = "vbench0", *srcip = "10.99.0.1", *dstip = "10.99.0.2", *dmac = NULL;
    uint64_t total = 4ull << 20;
    int dport = 9102, psize = 1400, opt;
    while ((opt = getopt(argc, argv, "i:S:D:M:b:P:s:")) != -1) {
        switch (opt) {
        case 'i': iface = optarg; break;
        case 'S': srcip = optarg; break;
        case 'D': dstip = optarg; break;
        case 'M': dmac = optarg; break;
        case 'b': total = strtoull(optarg, NULL, 10); break;
        case 'P': dport = atoi(optarg); break;
        case 's': psize = atoi(optarg); break;
        default: return 2;
        }
    }
    if (!dmac) { fprintf(stderr, "need -M dst_mac\n"); return 2; }
    if (psize < 1 || psize > 2048) { fprintf(stderr, "-s must be 1..2048\n"); return 2; }

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) { perror("AF_PACKET socket (needs CAP_NET_RAW)"); return 1; }

    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) { perror("SIOCGIFINDEX"); return 1; }
    int ifindex = ifr.ifr_ifindex;
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) { perror("SIOCGIFHWADDR"); return 1; }
    uint8_t smac[6]; memcpy(smac, ifr.ifr_hwaddr.sa_data, 6);
    uint8_t dm[6]; if (parse_mac(dmac, dm) < 0) { fprintf(stderr, "bad mac\n"); return 2; }

    struct sockaddr_ll sll = {0};
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_halen = 6;
    memcpy(sll.sll_addr, dm, 6);

    /* frame buffer: eth(14) + ip(20) + udp(8) + payload */
    uint8_t frame[14 + 20 + 8 + 2048];
    struct ethhdr *eth = (void *)frame;
    memcpy(eth->h_dest, dm, 6);
    memcpy(eth->h_source, smac, 6);
    eth->h_proto = htons(ETH_P_IP);

    struct iphdr { uint8_t vhl, tos; uint16_t tot; uint16_t id, off;
                   uint8_t ttl, proto; uint16_t csum; uint32_t s, d; } __attribute__((packed));
    struct udphdr { uint16_t sport, dport, len, csum; } __attribute__((packed));
    struct iphdr *ip = (void *)(frame + 14);
    struct udphdr *udp = (void *)(frame + 14 + 20);
    uint8_t *payload = frame + 14 + 20 + 8;
    memset(payload, 0x9C, psize);

    uint32_t sip, dip;
    inet_pton(AF_INET, srcip, &sip);
    inet_pton(AF_INET, dstip, &dip);

    uint64_t app_sent = 0;
    uint64_t nframes = (total + psize - 1) / psize;
    for (uint64_t i = 0; i < nframes; i++) {
        int plen = psize;
        if ((i + 1) * (uint64_t)psize > total) plen = (int)(total - i * (uint64_t)psize);
        int iptot = 20 + 8 + plen;
        memset(ip, 0, 20);
        ip->vhl = 0x45; ip->tos = 0; ip->tot = htons(iptot);
        ip->id = htons((uint16_t)i); ip->off = 0; ip->ttl = 64; ip->proto = IPPROTO_UDP;
        ip->s = sip; ip->d = dip; ip->csum = 0;
        ip->csum = csum16(ip, 20, 0);
        udp->sport = htons(40000); udp->dport = htons(dport);
        udp->len = htons(8 + plen); udp->csum = 0;   /* UDP csum optional in IPv4 */
        int flen = 14 + iptot;
        ssize_t w = sendto(fd, frame, flen, 0, (struct sockaddr *)&sll, sizeof sll);
        if (w > 0) app_sent += (uint64_t)plen;   /* count UDP payload as the "transferred" amount */
        else break;
    }
    close(fd);
    printf("RESULT app_sent=%llu app_recv=0 proto=afpacket dir=up peer=%s lport=40000 rport=%d pid=%d exe=%s\n",
           (unsigned long long)app_sent, dstip, dport, (int)getpid(), argv[0]);
    return 0;
}
