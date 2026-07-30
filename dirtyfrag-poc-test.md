# Dirty Frag PoC Test for Hardened Containers

Validates whether DataRobot containers are reachable for the two Dirty Frag CVEs:

- **CVE-2026-43284** — xfrm-ESP Page-Cache Write
- **CVE-2026-43500** — RxRPC Page-Cache Write

## Approach

For "minimum-steps proof in a hardened container," running the full Dirty Frag chain is overkill. The cleanest test is **syscall reachability** — if the syscalls the bug needs aren't reachable from the container, the bug isn't reachable, period. Two ~10-second checks, zero filesystem changes, zero kernel state risk.

## Reachability test

Drop this into a pod (e.g. `kubectl exec -it <pod> -- python3 -`):

```python
import ctypes, errno, os, socket

libc = ctypes.CDLL("libc.so.6", use_errno=True)
CLONE_NEWUSER, CLONE_NEWNET, AF_RXRPC, NETLINK_XFRM = 0x10000000, 0x40000000, 33, 6

# CVE-2026-43500 (RxRPC) — needs only AF_RXRPC socket
try:
    s = socket.socket(AF_RXRPC, socket.SOCK_DGRAM, 0); s.close()
    print("RxRPC: REACHABLE  -> container is vulnerable to CVE-2026-43500")
except OSError as e:
    print(f"RxRPC: blocked    ({e.strerror})")

# CVE-2026-43284 (xfrm-ESP) — needs userns + NETLINK_XFRM
if libc.unshare(CLONE_NEWUSER | CLONE_NEWNET) != 0:
    print(f"xfrm-ESP: blocked at unshare ({os.strerror(ctypes.get_errno())})")
else:
    try:
        s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_XFRM); s.close()
        print("xfrm-ESP: REACHABLE -> container is vulnerable to CVE-2026-43284")
    except OSError as e:
        print(f"xfrm-ESP: userns ok but NETLINK_XFRM blocked ({e.strerror})")
```

## Expected output on a properly hardened pod

A pod with `capabilities.drop: [ALL]` + `seccompProfile: RuntimeDefault` should produce:

- `RxRPC: REACHABLE` — this is the known gap; expected to fail until the `rxrpc` module is blacklisted on the node.
- `xfrm-ESP: blocked at unshare (Operation not permitted)` — confirms the cap-drop + RuntimeDefault mitigation.

If both lines say "blocked," the container is closed to both CVEs without running any actual exploit code.

## Optional: end-to-end "wrote one byte to a read-only file" demo

If a leadership readout needs to *see* a file change rather than syscall output, the public PoC at [V4bel/dirtyfrag](https://github.com/V4bel/dirtyfrag) already does this. `exp.c` is built to demonstrate the page-cache write primitive against an arbitrary file. To make it harmless, point it at a controlled target:

1. As root on the node (or in a separate test pod):
   ```
   echo "before" > /tmp/dirtyfrag-target && chmod 0444 /tmp/dirtyfrag-target
   ```
2. Modify the PoC's target path to `/tmp/dirtyfrag-target`.
3. Run as a non-root user inside the container under test; verify the byte changed.
4. **Cleanup** (per the upstream README):
   ```
   echo 3 > /proc/sys/vm/drop_caches
   ```
   on the node afterwards — the page cache will be polluted for any other process reading any file the exploit touched.

## Cautions

- The PoC has a non-zero rate of leaving the node in a degraded state until cache drop / reboot. Run only on a node you own and can recycle, not shared CI infra.
- The reachability test above proves the same thing for hardening-validation purposes. Reserve the full PoC for cases where someone really needs to *see* a file change.
- If reachability says "blocked" for both, there is nothing to demonstrate end-to-end.

## Scope

Authorized testing on DataRobot's own staging infrastructure (ci-stg tenant). Do not run against shared/production nodes.
