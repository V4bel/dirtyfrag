# Dirty Frag CVE reachability check — run output

Run target: DataRobot staging Custom App pod (`jira-hello-world`, id `69fea661b9a3e1352d5e201a`).
Compiled inside the pod via the Streamlit "Compile + run" path.

```
$ gcc -O0 -Wall -o /tmp/hello /tmp/hello.c
[exit 0]

$ /tmp/hello
[exit 0]
```

```
Dirty Frag CVE reachability + diagnostic check
Run from inside the container under test. Read-only, non-destructive.

========================================================================
CVE-2026-43500 - RxRPC Page-Cache Write
========================================================================
  Family:    Dirty Frag chain
  NVD:       https://nvd.nist.gov/vuln/detail/CVE-2026-43500
  Write-up:  https://github.com/V4bel/dirtyfrag
  Trigger:   socket(AF_RXRPC, ...) - no caps, no namespace needed
  Distinct:  Reaches the bug WITHOUT requiring CAP_NET_ADMIN or a
             user namespace - so seccomp+caps alone do not stop it.
             Mitigation must be node-level (rxrpc.ko unload/blacklist).

  Reachability: blocked (Address family not supported by protocol, errno 97)

  Why (kernel module presence):
    AF_RXRPC in /proc/net/protocols: false
    rxrpc.ko loaded:                 false
    /sys/module/rxrpc/initstate:     <unreadable: No such file or directory>

========================================================================
CVE-2026-43284 - xfrm-ESP Page-Cache Write
========================================================================
  Family:    Dirty Frag chain (patched mainline 2026-05-08)
  NVD:       https://nvd.nist.gov/vuln/detail/CVE-2026-43284
  Write-up:  https://github.com/V4bel/dirtyfrag
  Trigger:   XFRM_MSG_NEWSA over NETLINK_XFRM - requires CAP_NET_ADMIN
             PoC escape: unshare(CLONE_NEWUSER|CLONE_NEWNET) to acquire
             CAP_NET_ADMIN inside a fresh user namespace.
  Distinct:  Two-step attack. Standard hardening (drop ALL caps +
             RuntimeDefault seccomp denying CLONE_NEWUSER) blocks both
             rungs of the ladder.

  Reachability: blocked - esp4.ko/esp6.ko not loaded on node
                (NETLINK_XFRM socket may be reachable but SA
                 registration returns EPROTONOSUPPORT)

  Why (which layer blocks):
    esp4.ko loaded on node:                        false
    esp6.ko loaded on node:                        false
    Seccomp:                                       0  (2 = filter active)
    NoNewPrivs:                                    1
    CapEff:                                        0000000000000000  (0 = no caps)
    /proc/sys/user/max_user_namespaces:            63359
    /proc/sys/kernel/unprivileged_userns_clone:    <unreadable: No such file or directory>
    AppArmor/SELinux (/proc/self/attr/current):    system_u:system_r:container_t:s0:c31,c101
    uid_map (in initial userns?):                           0          0 4294967295

  Per-flag unshare (distinguishes cap check from seccomp):
    unshare(CLONE_NEWUSER ): OK
    unshare(CLONE_NEWNET  ): Operation not permitted
    unshare(CLONE_NEWNS   ): Operation not permitted
    unshare(CLONE_NEWPID  ): Operation not permitted

========================================================================
Summary
========================================================================
  NOT EXPLOITABLE - CVE-2026-43500 RxRPC - rxrpc kernel module not loaded on node
  NOT EXPLOITABLE - CVE-2026-43284 xfrm-ESP - neither esp4 nor esp6 module loaded on node (no ESP handler registered)

------ copy-paste summary ------
NOT EXPLOITABLE - CVE-2026-43500 RxRPC - rxrpc kernel module not loaded on node
NOT EXPLOITABLE - CVE-2026-43284 xfrm-ESP - neither esp4 nor esp6 module loaded on node (no ESP handler registered)
--------------------------------
```
