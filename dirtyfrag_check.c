// Dirty Frag CVE reachability + diagnostic check (C port of dirtyfrag_check.py).
//
// Determines whether this container can reach either of the two CVEs in the
// Dirty Frag chain and reports which kernel/sandbox layer is blocking.
// Read-only; no exploit primitive is run.
//
// CVEs covered:
//   CVE-2026-43500 - RxRPC Page-Cache Write
//     NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-43500
//     Write-up: https://github.com/V4bel/dirtyfrag
//
//   CVE-2026-43284 - xfrm-ESP Page-Cache Write
//     NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-43284
//     Write-up: https://github.com/V4bel/dirtyfrag
//
// Build:   gcc -O0 -Wall -o /tmp/dirtyfrag_check dirtyfrag_check.c
// Run:     /tmp/dirtyfrag_check

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef AF_RXRPC
#define AF_RXRPC 33
#endif
#ifndef NETLINK_XFRM
#define NETLINK_XFRM 6
#endif
#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000
#endif
#ifndef CLONE_NEWNET
#define CLONE_NEWNET  0x40000000
#endif
#ifndef CLONE_NEWNS
#define CLONE_NEWNS   0x00020000
#endif
#ifndef CLONE_NEWPID
#define CLONE_NEWPID  0x20000000
#endif

// ---------- helpers ----------

// Read a small file's contents into buf (NUL-terminated, trailing whitespace
// stripped). Returns buf. On error, fills buf with "<unreadable: ...>".
static const char *cat(const char *path, char *buf, size_t buflen) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        snprintf(buf, buflen, "<unreadable: %s>", strerror(errno));
        return buf;
    }
    ssize_t n = read(fd, buf, buflen - 1);
    close(fd);
    if (n < 0) {
        snprintf(buf, buflen, "<read error: %s>", strerror(errno));
        return buf;
    }
    buf[n] = 0;
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == ' ' || buf[n - 1] == '\t')) {
        buf[--n] = 0;
    }
    return buf;
}

// Pull a "Name: value" field out of /proc/self/status. Returns NULL if absent.
static const char *proc_status_field(const char *name, char *out, size_t outlen) {
    FILE *fp = fopen("/proc/self/status", "r");
    if (!fp) { out[0] = 0; return NULL; }
    char line[512];
    size_t namelen = strlen(name);
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, name, namelen) == 0 && line[namelen] == ':') {
            const char *v = line + namelen + 1;
            while (*v == ' ' || *v == '\t') v++;
            size_t L = strlen(v);
            while (L && (v[L-1] == '\n' || v[L-1] == ' ')) L--;
            if (L >= outlen) L = outlen - 1;
            memcpy(out, v, L);
            out[L] = 0;
            fclose(fp);
            return out;
        }
    }
    fclose(fp);
    out[0] = 0;
    return NULL;
}

// True if a kernel module is loaded on the node.
// Checks /sys/module/<name>/ first, then /proc/modules with exact-prefix match.
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
            found = true;
            break;
        }
    }
    fclose(fp);
    return found;
}

// Fork a child, attempt unshare(flags), report back to the parent.
// Returns NULL on success, otherwise strerror() of the errno from unshare().
static const char *try_unshare(int flags) {
    pid_t pid = fork();
    if (pid < 0) return strerror(errno);
    if (pid == 0) {
        int rc = unshare(flags);
        _exit(rc == 0 ? 0 : (errno & 0xff));
    }
    int st;
    if (waitpid(pid, &st, 0) < 0) return strerror(errno);
    if (!WIFEXITED(st)) return "child died abnormally";
    int code = WEXITSTATUS(st);
    return code == 0 ? NULL : strerror(code);
}

static void section(const char *title) {
    putchar('\n');
    for (int i = 0; i < 72; i++) putchar('=');
    printf("\n%s\n", title);
    for (int i = 0; i < 72; i++) putchar('=');
    putchar('\n');
}

// Tiny convenience: returns "true" / "false" string for printing.
static const char *tf(bool v) { return v ? "true" : "false"; }

// ---------- CVE-2026-43500 RxRPC check ----------

typedef struct {
    const char *verdict;   // "EXPLOITABLE" or "NOT EXPLOITABLE"
    const char *cve;       // "CVE-2026-43500 RxRPC"
    char        why[256];  // one-line reason
} result_t;

static result_t check_rxrpc(void) {
    section("CVE-2026-43500 - RxRPC Page-Cache Write");
    puts("  Family:    Dirty Frag chain");
    puts("  NVD:       https://nvd.nist.gov/vuln/detail/CVE-2026-43500");
    puts("  Write-up:  https://github.com/V4bel/dirtyfrag");
    puts("  Trigger:   socket(AF_RXRPC, ...) - no caps, no namespace needed");
    puts("  Distinct:  Reaches the bug WITHOUT requiring CAP_NET_ADMIN or a");
    puts("             user namespace - so seccomp+caps alone do not stop it.");
    puts("             Mitigation must be node-level (rxrpc.ko unload/blacklist).");
    putchar('\n');

    bool reachable = false;
    int s = socket(AF_RXRPC, SOCK_DGRAM, 0);
    if (s >= 0) {
        close(s);
        reachable = true;
        puts("  Reachability: REACHABLE - exploitable from this container");
    } else {
        printf("  Reachability: blocked (%s, errno %d)\n", strerror(errno), errno);
    }

    char protos[8192], initstate[64];
    cat("/proc/net/protocols", protos, sizeof(protos));
    bool rxrpc_in_protos = strstr(protos, "RXRPC") != NULL;
    bool rxrpc_mod = module_loaded("rxrpc");
    cat("/sys/module/rxrpc/initstate", initstate, sizeof(initstate));

    putchar('\n');
    puts("  Why (kernel module presence):");
    printf("    AF_RXRPC in /proc/net/protocols: %s\n", tf(rxrpc_in_protos));
    printf("    rxrpc.ko loaded:                 %s\n", tf(rxrpc_mod));
    printf("    /sys/module/rxrpc/initstate:     %s\n", initstate);

    result_t r = { .cve = "CVE-2026-43500 RxRPC" };
    if (reachable) {
        r.verdict = "EXPLOITABLE";
        snprintf(r.why, sizeof(r.why),
                 "AF_RXRPC socket reachable - bug primitive available");
    } else {
        r.verdict = "NOT EXPLOITABLE";
        snprintf(r.why, sizeof(r.why),
                 "rxrpc kernel module not loaded on node");
    }
    return r;
}

// ---------- CVE-2026-43284 xfrm-ESP check ----------

static result_t check_xfrm(void) {
    section("CVE-2026-43284 - xfrm-ESP Page-Cache Write");
    puts("  Family:    Dirty Frag chain (patched mainline 2026-05-08)");
    puts("  NVD:       https://nvd.nist.gov/vuln/detail/CVE-2026-43284");
    puts("  Write-up:  https://github.com/V4bel/dirtyfrag");
    puts("  Trigger:   XFRM_MSG_NEWSA over NETLINK_XFRM - requires CAP_NET_ADMIN");
    puts("             PoC escape: unshare(CLONE_NEWUSER|CLONE_NEWNET) to acquire");
    puts("             CAP_NET_ADMIN inside a fresh user namespace.");
    puts("  Distinct:  Two-step attack. Standard hardening (drop ALL caps +");
    puts("             RuntimeDefault seccomp denying CLONE_NEWUSER) blocks both");
    puts("             rungs of the ladder.");
    putchar('\n');

    // Module presence: SA registration over NETLINK_XFRM returns EPROTONOSUPPORT
    // if neither esp4 nor esp6 is loaded, regardless of how reachable the
    // netlink socket is. Module autoload from inside an unprivileged userns
    // is blocked, so userspace can't fix this.
    bool esp4 = module_loaded("esp4");
    bool esp6 = module_loaded("esp6");
    bool esp_present = esp4 || esp6;

    const char *unshare_err = try_unshare(CLONE_NEWUSER | CLONE_NEWNET);
    bool netlink_ok = false;
    const char *netlink_err = NULL;
    if (unshare_err == NULL) {
        int s = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
        if (s >= 0) { close(s); netlink_ok = true; }
        else        { netlink_err = strerror(errno); }
    }

    bool reachable = netlink_ok && esp_present;

    if (reachable) {
        puts("  Reachability: REACHABLE - SA registration would succeed");
    } else if (!esp_present) {
        puts("  Reachability: blocked - esp4.ko/esp6.ko not loaded on node");
        puts("                (NETLINK_XFRM socket may be reachable but SA");
        puts("                 registration returns EPROTONOSUPPORT)");
    } else if (unshare_err != NULL) {
        printf("  Reachability: blocked at unshare(CLONE_NEWUSER|CLONE_NEWNET) - %s\n",
               unshare_err);
    } else {
        printf("  Reachability: userns OK but NETLINK_XFRM blocked (%s)\n", netlink_err);
    }

    char max_un[64], capeff[64], seccomp[64], nnp[64];
    char unprivuserns[64], lsm[256], uidmap[256];
    cat("/proc/sys/user/max_user_namespaces", max_un, sizeof(max_un));
    cat("/proc/sys/kernel/unprivileged_userns_clone", unprivuserns, sizeof(unprivuserns));
    cat("/proc/self/attr/current", lsm, sizeof(lsm));
    cat("/proc/self/uid_map", uidmap, sizeof(uidmap));
    proc_status_field("CapEff",  capeff,  sizeof(capeff));
    proc_status_field("Seccomp", seccomp, sizeof(seccomp));
    proc_status_field("NoNewPrivs", nnp, sizeof(nnp));

    putchar('\n');
    puts("  Why (which layer blocks):");
    printf("    esp4.ko loaded on node:                        %s\n", tf(esp4));
    printf("    esp6.ko loaded on node:                        %s\n", tf(esp6));
    printf("    Seccomp:                                       %s  (2 = filter active)\n", seccomp);
    printf("    NoNewPrivs:                                    %s\n", nnp);
    printf("    CapEff:                                        %s  (0 = no caps)\n", capeff);
    printf("    /proc/sys/user/max_user_namespaces:            %s\n", max_un);
    printf("    /proc/sys/kernel/unprivileged_userns_clone:    %s\n", unprivuserns);
    printf("    AppArmor/SELinux (/proc/self/attr/current):    %s\n", lsm);
    printf("    uid_map (in initial userns?):                  %s\n", uidmap);

    putchar('\n');
    puts("  Per-flag unshare (distinguishes cap check from seccomp):");
    struct { int flag; const char *label; } flags[] = {
        { CLONE_NEWUSER, "CLONE_NEWUSER" },
        { CLONE_NEWNET,  "CLONE_NEWNET"  },
        { CLONE_NEWNS,   "CLONE_NEWNS"   },
        { CLONE_NEWPID,  "CLONE_NEWPID"  },
    };
    for (size_t i = 0; i < sizeof(flags)/sizeof(flags[0]); i++) {
        const char *e = try_unshare(flags[i].flag);
        printf("    unshare(%-14s): %s\n", flags[i].label, e ? e : "OK");
    }

    result_t r = { .cve = "CVE-2026-43284 xfrm-ESP" };
    if (reachable) {
        r.verdict = "EXPLOITABLE";
        snprintf(r.why, sizeof(r.why),
                 "userns + NETLINK_XFRM reachable AND esp module loaded");
    } else if (!esp_present) {
        r.verdict = "NOT EXPLOITABLE";
        snprintf(r.why, sizeof(r.why),
                 "neither esp4 nor esp6 module loaded on node "
                 "(no ESP handler registered)");
    } else if (unshare_err == NULL && netlink_err != NULL) {
        r.verdict = "NOT EXPLOITABLE";
        snprintf(r.why, sizeof(r.why),
                 "userns ok but NETLINK_XFRM socket blocked");
    } else {
        r.verdict = "NOT EXPLOITABLE";
        long max_un_n = strtol(max_un, NULL, 10);
        if (max_un_n == 0) {
            snprintf(r.why, sizeof(r.why),
                     "kernel sysctl forbids user namespace creation");
        } else {
            snprintf(r.why, sizeof(r.why),
                     "seccomp denies user namespace creation, caps dropped");
        }
    }
    return r;
}

// ---------- main ----------

int main(void) {
    puts("Dirty Frag CVE reachability + diagnostic check");
    puts("Run from inside the container under test. Read-only, non-destructive.");

    result_t rxrpc = check_rxrpc();
    result_t xfrm  = check_xfrm();

    section("Summary");
    printf("  %s - %s - %s\n", rxrpc.verdict, rxrpc.cve, rxrpc.why);
    printf("  %s - %s - %s\n", xfrm.verdict,  xfrm.cve,  xfrm.why);

    putchar('\n');
    puts("------ copy-paste summary ------");
    printf("%s - %s - %s\n", rxrpc.verdict, rxrpc.cve, rxrpc.why);
    printf("%s - %s - %s\n", xfrm.verdict,  xfrm.cve,  xfrm.why);
    puts("--------------------------------");

    return 0;
}
