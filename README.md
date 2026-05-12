# Dirty Frag (aarch64 port)

> Port of [V4bel/dirtyfrag](https://github.com/V4bel/dirtyfrag) to 64-bit ARM (aarch64).
> The original vulnerability discovery, write-up, and exploit are by
> **[Hyunwoo Kim (@v4bel)](https://x.com/v4bel)**. This repository only adapts the
> embedded payload and verification logic so the exploit lands on aarch64 Linux.

## Abstract

Dirty Frag chains two page-cache write vulnerabilities — `xfrm-ESP Page-Cache Write
(CVE-2026-43284)` and `RxRPC Page-Cache Write (CVE-2026-43500)` — into a universal
local privilege escalation. The upstream PoC ships with an x86_64-only payload
(both the planted ELF and the verification logic). On aarch64 distributions the
underlying kernel bugs are still present and the **xfrm-ESP primitive itself works
unmodified** — only the userspace logic prematurely declares failure because it
checks for x86 byte signatures.

This port replaces:

1. the 192-byte embedded x86_64 root-shell ELF with an aarch64 equivalent
   (`e_machine = 0xb7`, `MOVZ` / `SVC #0` shellcode, aarch64 syscall numbers
   `setgid=144`, `setuid=146`, `setgroups=159`, `execve=221`);
2. the post-write `verify_byte()` check, which previously looked for the x86
   prologue `0x31 0xff` at the entry offset — now checks for the aarch64
   `MOVZ` opcode bytes `0x80 0xd2` at offsets `0x7a/0x7b`;
3. the `su_marker[]` array used by `su_already_patched()` — now holds the first
   eight bytes of the aarch64 shellcode (`00 00 80 d2 08 12 80 d2`).

These are the only three changes against upstream. The kernel-side primitive
(`xfrm-ESP` page-cache write via `splice` + `vmsplice`) is unchanged.

## What works / what doesn't on aarch64

| Leg                           | x86_64 | aarch64        | Notes                                                                                                                                              |
| ----------------------------- | ------ | -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `xfrm-ESP` page-cache write   | works  | **works**      | Uses real `struct page*` via `splice` from the target file. Cache-coherency differences do not affect the write path.                              |
| `RxRPC` page-cache write      | works  | **kernel oops**| Supplies a fabricated `struct page*` that x86 `flush_dcache_page()` ignores (no-op) but aarch64 dereferences (real cache flush) → translation fault. |

Because the xfrm-ESP leg succeeds on aarch64, the rxrpc fallback is unnecessary
and the exploit obtains a root shell through the same flow as upstream.

If you only have access to a distribution that blocks unprivileged user-namespace
creation (e.g., Ubuntu under AppArmor), the xfrm-ESP leg will not run. On those
systems the rxrpc fallback is currently not portable to aarch64 — see
*Limitations* below.

## Exploiting

```
git clone https://github.com/Zi1chs/dirtyfrag.git && \
  cd dirtyfrag-aarch64 && \
  gcc -O0 -Wall -o exp exp.c -lutil && \
  ./exp
```

Pass `-v` or set `DIRTYFRAG_VERBOSE=1` to see the patching progress.

This PoC is for authorized testing only. Do not run it on systems you do not
own or are not contracted to test.

## Cleanup

After running the exploit, the page cache for `/usr/bin/su` is polluted. Either
drop the caches or reboot:

```
echo 3 | sudo tee /proc/sys/vm/drop_caches
```

The on-disk binary is not modified — only the in-memory page cache is.

## Tested

- Kali ARM (Apple Silicon, VMware Fusion), kernel `6.19.11+kali-arm64`, glibc
  built for `aarch64-linux-gnu`. Both modules `esp4` and `xfrm_user` autoload
  cleanly on first use; unprivileged user namespaces are enabled by default.

If you test this on additional aarch64 distributions (Raspberry Pi OS, Ubuntu
Server for ARM, openSUSE aarch64, Fedora aarch64, Amazon Linux 2023 aarch64,
Oracle Linux ARM, etc.) please open an issue or PR with the kernel version and
result.

## Affected versions

Same scope as upstream — these are kernel bugs, not architecture-specific:

- **CVE-2026-43284** (xfrm-ESP): `cac2661c53f3` (2017-01-17) → `f4c50a4034e6` (2026-05-05)
- **CVE-2026-43500** (RxRPC):     `2dc334f1a63a` (2023-06-08) → `aa54b1d27fe0` (2026-05-10)

Kernels built before those fix commits are vulnerable. As of this port's
publication the patches are in mainline but have not yet been backported to
every aarch64 distribution.

## Mitigation

Same as upstream:

```
sudo sh -c "printf 'install esp4 /bin/false\ninstall esp6 /bin/false\ninstall rxrpc /bin/false\n' \
  > /etc/modprobe.d/dirtyfrag.conf; rmmod esp4 esp6 rxrpc 2>/dev/null; \
  echo 3 > /proc/sys/vm/drop_caches; true"
```

Update to a kernel that includes both fix commits as soon as your distribution
ships the backport.

## Limitations

- **rxrpc fallback is not ported.** On aarch64 the rxrpc primitive faults the
  kernel in `flush_dcache_page` because of how the bug constructs a fake
  `struct page*`. Making that leg work would require a different page-supply
  technique (real backing page that aliases the target file's page cache),
  which is a research problem, not a code change.
- **Only `/usr/bin/su` is patched.** The `/etc/passwd` backdoor path used by
  the rxrpc leg is unavailable on aarch64 for the reason above. If your target
  distribution restricts unprivileged userns and you cannot use the xfrm-ESP
  leg either, this port will not give you root.

## Credit

- Original vulnerability discovery, write-up, and exploit: **Hyunwoo Kim
  ([@v4bel](https://x.com/v4bel))** — see upstream repo
  [V4bel/dirtyfrag](https://github.com/V4bel/dirtyfrag) and the technical
  write-up linked from there.
- aarch64 port (this repo): payload + verification adapted to aarch64 only;
  all kernel-exploitation logic is upstream's.

## License

The upstream repository does not ship an explicit license file. This fork
preserves attribution and is published for security-research purposes only.
If the upstream author requests removal or relicensing, please open an issue
and the repository will be updated accordingly.
