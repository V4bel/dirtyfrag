#!/usr/bin/env python3
"""
Dirty Frag CVE reachability + diagnostic check.
Determines whether the container running this script is exploitable by either
of the two CVEs that make up the Dirty Frag chain, and reports which
kernel/sandbox layer is doing the blocking.

CVEs covered:
  CVE-2026-43500 - RxRPC Page-Cache Write
    NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-43500
    Write-up: https://github.com/V4bel/dirtyfrag

  CVE-2026-43284 - xfrm-ESP Page-Cache Write
    NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-43284
    Write-up: https://github.com/V4bel/dirtyfrag
"""

import os, ctypes, socket

libc = ctypes.CDLL("libc.so.6", use_errno=True)

CLONE_NEWUSER = 0x10000000
CLONE_NEWNET  = 0x40000000
CLONE_NEWNS   = 0x00020000
CLONE_NEWPID  = 0x20000000
AF_RXRPC      = 33
NETLINK_XFRM  = 6


def cat(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError as e:
        return f"<unreadable: {e.strerror}>"


def proc_status_field(name):
    for line in cat('/proc/self/status').splitlines():
        if line.startswith(name + ':'):
            return line.split(':', 1)[1].strip()
    return None


def module_loaded(name):
    """Returns True if a kernel module is loaded on the node.

    Checks /sys/module/<name>/ first (most reliable), then /proc/modules
    with an exact-prefix match (avoids substring false-positives like
    'esp_scsi' matching 'esp').
    """
    try:
        os.stat(f"/sys/module/{name}")
        return True
    except OSError:
        pass
    try:
        with open("/proc/modules") as f:
            for line in f:
                if line.startswith(name + " "):
                    return True
    except OSError:
        pass
    return False


def try_unshare(flags):
    pid = os.fork()
    if pid == 0:
        rc = libc.unshare(flags)
        os._exit(0 if rc == 0 else ctypes.get_errno())
    _, status = os.waitpid(pid, 0)
    code = os.WEXITSTATUS(status)
    return None if code == 0 else os.strerror(code)


def section(title):
    print()
    print("=" * 72)
    print(title)
    print("=" * 72)


# ---------------------------------------------------------------------------
# CVE-2026-43500 - RxRPC Page-Cache Write
# ---------------------------------------------------------------------------
def check_rxrpc():
    section("CVE-2026-43500 - RxRPC Page-Cache Write")
    print("  Family:    Dirty Frag chain")
    print("  NVD:       https://nvd.nist.gov/vuln/detail/CVE-2026-43500")
    print("  Write-up:  https://github.com/V4bel/dirtyfrag")
    print("  Trigger:   socket(AF_RXRPC, ...) - no caps, no namespace needed")
    print("  Distinct:  Reaches the bug WITHOUT requiring CAP_NET_ADMIN or a")
    print("             user namespace - so seccomp+caps alone do not stop it.")
    print("             Mitigation must be node-level (rxrpc.ko unload/blacklist).")
    print()

    try:
        s = socket.socket(AF_RXRPC, socket.SOCK_DGRAM, 0)
        s.close()
        reachable = True
        print("  Reachability: REACHABLE - exploitable from this container")
    except OSError as e:
        reachable = False
        print(f"  Reachability: blocked ({e.strerror}, errno {e.errno})")

    print()
    print("  Why (kernel module presence):")
    print(f"    AF_RXRPC in /proc/net/protocols: {'RXRPC' in cat('/proc/net/protocols')}")
    print(f"    rxrpc.ko loaded:                 {module_loaded('rxrpc')}")
    print(f"    /sys/module/rxrpc/initstate:     {cat('/sys/module/rxrpc/initstate')}")

    if reachable:
        return ("EXPLOITABLE", "CVE-2026-43500 RxRPC",
                "AF_RXRPC socket reachable - bug primitive available")
    return ("NOT EXPLOITABLE", "CVE-2026-43500 RxRPC",
            "rxrpc kernel module not loaded on node")


# ---------------------------------------------------------------------------
# CVE-2026-43284 - xfrm-ESP Page-Cache Write
# ---------------------------------------------------------------------------
def check_xfrm():
    section("CVE-2026-43284 - xfrm-ESP Page-Cache Write")
    print("  Family:    Dirty Frag chain (patched mainline 2026-05-08)")
    print("  NVD:       https://nvd.nist.gov/vuln/detail/CVE-2026-43284")
    print("  Write-up:  https://github.com/V4bel/dirtyfrag")
    print("  Trigger:   XFRM_MSG_NEWSA over NETLINK_XFRM - requires CAP_NET_ADMIN")
    print("             PoC escape: unshare(CLONE_NEWUSER|CLONE_NEWNET) to acquire")
    print("             CAP_NET_ADMIN inside a fresh user namespace.")
    print("  Distinct:  Two-step attack. Standard hardening (drop ALL caps +")
    print("             RuntimeDefault seccomp denying CLONE_NEWUSER) blocks both")
    print("             rungs of the ladder.")
    print()

    # Module presence on the node. SA registration over NETLINK_XFRM returns
    # EPROTONOSUPPORT if neither esp4.ko nor esp6.ko is loaded, regardless of
    # how reachable the netlink socket itself is. Module autoload is blocked
    # from inside an unprivileged userns, so userspace can't fix this.
    esp4 = module_loaded("esp4")
    esp6 = module_loaded("esp6")
    esp_present = esp4 or esp6

    err = try_unshare(CLONE_NEWUSER | CLONE_NEWNET)
    netlink_err = None
    if err is None:
        try:
            s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_XFRM)
            s.close()
            netlink_ok = True
        except OSError as e:
            netlink_err = e.strerror
            netlink_ok = False
    else:
        netlink_ok = False

    # Reachability now requires BOTH the sandbox-passable path (userns +
    # netlink) AND the kernel actually having an ESP protocol handler.
    reachable = netlink_ok and esp_present

    if reachable:
        print("  Reachability: REACHABLE - SA registration would succeed")
    elif not esp_present:
        print("  Reachability: blocked - esp4.ko/esp6.ko not loaded on node")
        print("                (NETLINK_XFRM socket is reachable but SA registration")
        print("                 returns EPROTONOSUPPORT without an ESP handler)")
    elif err is not None:
        print(f"  Reachability: blocked at unshare(CLONE_NEWUSER|CLONE_NEWNET) - {err}")
    else:
        print(f"  Reachability: userns OK but NETLINK_XFRM blocked ({netlink_err})")

    max_un_str = cat('/proc/sys/user/max_user_namespaces')
    cap_eff = proc_status_field('CapEff')
    seccomp = proc_status_field('Seccomp')

    print()
    print("  Why (which layer blocks):")
    print(f"    esp4.ko loaded on node:                        {esp4}")
    print(f"    esp6.ko loaded on node:                        {esp6}")
    print(f"    Seccomp:                                       {seccomp}  (2 = filter active)")
    print(f"    NoNewPrivs:                                    {proc_status_field('NoNewPrivs')}")
    print(f"    CapEff:                                        {cap_eff}  (0 = no caps)")
    print(f"    /proc/sys/user/max_user_namespaces:            {max_un_str}")
    print(f"    /proc/sys/kernel/unprivileged_userns_clone:    {cat('/proc/sys/kernel/unprivileged_userns_clone')}")
    print(f"    AppArmor/SELinux (/proc/self/attr/current):    {cat('/proc/self/attr/current')}")
    print(f"    uid_map (in initial userns?):                  {cat('/proc/self/uid_map')}")
    print()
    print("  Per-flag unshare (distinguishes cap check from seccomp):")
    for flag, label in [
        (CLONE_NEWUSER, "CLONE_NEWUSER"),
        (CLONE_NEWNET,  "CLONE_NEWNET"),
        (CLONE_NEWNS,   "CLONE_NEWNS"),
        (CLONE_NEWPID,  "CLONE_NEWPID"),
    ]:
        e = try_unshare(flag)
        print(f"    unshare({label:<14}): {'OK' if e is None else e}")

    # Build the one-line "why". Module absence is the strongest blocker since
    # it can't be worked around from userspace.
    if reachable:
        why = "userns + NETLINK_XFRM reachable AND esp module loaded"
    elif not esp_present:
        why = "neither esp4 nor esp6 module loaded on node (no ESP handler registered)"
    elif err is None and netlink_err is not None:
        why = "userns ok but NETLINK_XFRM socket blocked"
    else:
        try:
            max_un = int(max_un_str)
            if max_un == 0:
                why = "kernel sysctl forbids user namespace creation"
            else:
                why = "seccomp denies user namespace creation, caps dropped"
        except (ValueError, TypeError):
            why = "user namespace creation blocked at unshare"

    if reachable:
        return ("EXPLOITABLE", "CVE-2026-43284 xfrm-ESP", why)
    return ("NOT EXPLOITABLE", "CVE-2026-43284 xfrm-ESP", why)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("Dirty Frag CVE reachability + diagnostic check")
    print("Run from inside the container under test. Save-only, non-destructive.")
    rxrpc_summary = check_rxrpc()
    xfrm_summary  = check_xfrm()

    section("Summary")
    print(f"  {rxrpc_summary[0]} - {rxrpc_summary[1]} - {rxrpc_summary[2]}")
    print(f"  {xfrm_summary[0]} - {xfrm_summary[1]} - {xfrm_summary[2]}")
    print()
