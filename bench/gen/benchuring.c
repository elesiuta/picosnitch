/* benchuring — TCP transfer whose data path runs entirely through io_uring.
 *
 * Establishes a normal TCP connection to benchserver, sends the framed header,
 * then performs the bulk transfer using io_uring send/recv submissions instead
 * of ordinary read()/write() syscalls. io_uring networking still calls the
 * socket's inet_sendmsg/inet_recvmsg in-kernel, so a monitor hooking those
 * kernel functions sees it; tools tracing send()/recv() syscalls do not.
 *
 * usage: benchuring -H <peer> -d up|down -b <bytes>
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <liburing.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAGIC 0x424E4348u
#define PORT_TCP 9101
#define CHUNK (1 << 16)
struct hdr { uint32_t magic; uint8_t mode; uint8_t proto; uint16_t pad; uint64_t nbytes; uint64_t rate; } __attribute__((packed));

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    const char *host = "10.99.0.2", *dir = "down";
    uint64_t nbytes = 10ull << 20;
    int opt;
    while ((opt = getopt(argc, argv, "H:d:b:")) != -1) {
        switch (opt) {
        case 'H': host = optarg; break;
        case 'd': dir = optarg; break;
        case 'b': nbytes = strtoull(optarg, NULL, 10); break;
        default: return 2;
        }
    }
    int is_up = strcmp(dir, "up") == 0;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET; a.sin_port = htons(PORT_TCP);
    inet_pton(AF_INET, host, &a.sin_addr);
    if (connect(fd, (void *)&a, sizeof a) < 0) { perror("connect"); return 1; }

    struct hdr h = {.magic = htonl(MAGIC), .mode = is_up ? 0 : 1, .proto = 6, .pad = 0,
                    .nbytes = htobe64(nbytes)};
    uint64_t app_sent = 0, app_recv = 0;
    if (send(fd, &h, sizeof h, 0) > 0) app_sent += sizeof h;

    struct io_uring ring;
    if (io_uring_queue_init(8, &ring, 0) < 0) { perror("io_uring_queue_init"); return 1; }
    uint8_t *buf = malloc(CHUNK);
    memset(buf, 0x44, CHUNK);
    uint64_t left = nbytes;
    while (left > 0) {
        size_t want = left > CHUNK ? CHUNK : (size_t)left;
        struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
        if (is_up) io_uring_prep_send(sqe, fd, buf, want, 0);
        else       io_uring_prep_recv(sqe, fd, buf, want, 0);
        io_uring_submit(&ring);
        struct io_uring_cqe *cqe;
        if (io_uring_wait_cqe(&ring, &cqe) < 0) break;
        int res = cqe->res;
        io_uring_cqe_seen(&ring, cqe);
        if (res <= 0) break;
        if (is_up) app_sent += (uint64_t)res; else app_recv += (uint64_t)res;
        left -= (uint64_t)res;
    }
    io_uring_queue_exit(&ring);

    struct sockaddr_in la; socklen_t ll = sizeof la; int lport = 0;
    if (getsockname(fd, (void *)&la, &ll) == 0) lport = ntohs(la.sin_port);
    close(fd);
    printf("RESULT app_sent=%llu app_recv=%llu want=%llu proto=tcp dir=%s peer=%s lport=%d rport=%d pid=%d exe=%s\n",
           (unsigned long long)app_sent, (unsigned long long)app_recv, (unsigned long long)nbytes,
           dir, host, lport, PORT_TCP, (int)getpid(), argv[0]);
    return 0;
}
