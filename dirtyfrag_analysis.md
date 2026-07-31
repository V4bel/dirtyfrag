# Dirty Frag — corrected risk assessment for staging Custom App pods

## TL;DR

```
NOT EXPLOITABLE - CVE-2026-43500 RxRPC - rxrpc kernel module not loaded on node
NOT EXPLOITABLE - CVE-2026-43284 xfrm-ESP - neither esp4 nor esp6 module loaded on node (no ESP handler registered)
```

The earlier `EXPLOITABLE` verdict for CVE-2026-43284 was misleading. The original `dirtyfrag_check.py` only verified that the `NETLINK_XFRM` socket was reachable and a user namespace could be acquired — necessary but not sufficient. The actual bug primitive needs an ESP protocol handler in the kernel's protocol table, which requires `esp4.ko` or `esp6.ko` to be loaded. On this node neither is loaded; XFRM_MSG_NEWSA returns `EPROTONOSUPPORT` before the bug code path is reached. Module autoload is blocked from inside an unprivileged userns, so userspace cannot fix this.

## Defense-in-depth picture

Run on jira-hello-world (id `69fea661b9a3e1352d5e201a`) on staging.datarobot.com, 2026-05-09.

| Layer | State | Notes |
|---|---|---|
| `esp4` / `esp6` / `rxrpc` modules | not loaded | Primary blocker. Absent on the node. |
| Seccomp filter | `0` (DISABLED) | No seccomp filter active. Earlier channel discussion assumed `RuntimeDefault` was applied — not the case here. |
| CapEff (effective caps) | `0000000000000000` | All caps dropped. Blocks bare `unshare(CLONE_NEWNET)`. |
| SELinux | `container_t` (enforcing) | Defense-in-depth. |
| `unshare(USER\|NET)` combined | OK | Two-step userns escape still works — caps gained inside the new userns satisfy the `NEWNET` check. |

## What this means

The only thing standing between this pod and Dirty Frag is **module absence on the node**. If `esp4`, `esp6`, or `rxrpc` ever gets loaded — legitimately (e.g. an IPsec configuration change, a feature pack) or via lateral movement — the userns escape is fully traversable on this pod's current config:

- Seccomp is off, so the syscall path is not gated.
- CapEff=0 blocks bare `unshare(CLONE_NEWNET)`, but the two-step `unshare(CLONE_NEWUSER | CLONE_NEWNET)` succeeds, since the second flag is checked against the freshly created userns where the process has full caps.
- SELinux's protection depends on whether `container_t` covers the `NETLINK_XFRM` and `AF_RXRPC` socket families. Worth confirming with the SELinux team.

## Recommended hardening (beyond keeping modules unloaded)

1. **Apply `RuntimeDefault` seccomp** on Custom App pods (currently `Seccomp=0`). RuntimeDefault denies `CLONE_NEWUSER` on most container runtimes and would close the userns escape unconditionally.
2. **Block `CLONE_NEWUSER` directly** via either an explicit seccomp profile or `kernel.unprivileged_userns_clone=0` at node level.
3. **Deploy the bpftrace daemonset** Paul/Brian sketched in the channel as a belt-and-suspenders that kills processes calling `socket(AF_RXRPC)` / opening ESP sockets, regardless of caps and namespaces.

## Tooling change

`dirtyfrag_check.py` was updated to gate the `EXPLOITABLE` verdict on actual module presence in addition to sandbox reachability. A C port (`dirtyfrag_check.c`) provides the same diagnostic for environments where running Python isn't convenient (e.g. the Streamlit "Compile + run" path used for this run).

## Tracking

- Slack: #cve-2026-43500-rxrpc-page-cache
- Jira: PRDSEC-1877
- Upstream write-up: https://github.com/V4bel/dirtyfrag
