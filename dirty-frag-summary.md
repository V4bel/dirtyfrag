# Dirty Frag (CVE-2026-43284 / CVE-2026-43500) — Current State

**Status as of 2026-05-10 13:22 PDT:** Mitigation tested in staging over the weekend; production rollout scheduled for Monday morning.

**The threat.** Dirty Frag is a chained LPE exploit disclosed 2026-05-08 with public PoC but no upstream patches at disclosure. Two CVEs: CVE-2026-43284 (xfrm-ESP) and CVE-2026-43500 (RxRPC). Bypasses the prior `algif_aead` blacklist that mitigated Copy Fail.

**Approach landed on.** Blacklist/prevent loading of `esp4`, `esp6`, and `afalg` kernel modules via a Kubernetes DaemonSet (`apply-modprobe-blacklist`). Bottlerocket and AL2023 each have their own variant. AMI-level kernel patch was deferred as riskier. Docs and verification steps live in `datarobot/small_scripts/copy-fail-friends`. PR: `ci-tf-modules-aws-amenities#423`. Ticket: COPS-18985, PRDSEC-1877.

**Verification.** Artem ran the public exploit against staging custom apps, custom models, image-builder, and notebooks — none exploitable with mitigation applied. SLA jobs green. Chronosphere logs show no instances had `esp4`/`esp6` actually loaded. Notably, exploit failed even after manually loading `esp4` on both Bottlerocket and AL2023 — possible the 6.1.x kernel isn't affected by CVE-2026-43284 at all. Crowdstrike confirmed detection coverage for both CVEs.

**Rollout plan.**
- Monday AM (2026-05-11): deploy to production MTS, fleet engineers available
- Then: STS rollout, timeline TBD
- No verified attack method against our env, so Stas opted to avoid a Sunday-night IR risk

**Open exposure.** STS clusters not yet mitigated. Non-AWS environments (GCP, Azure, Nebius, Oracle, OpenShift, Boston lab) not addressed by the AWS-focused DaemonSet.

## Ideas that were reversed during the week

- **"We're already defended against CVE-2026-43284 via seccomp + cap-drop."** Peter's initial Claude-Code reachability analysis claimed this; he retracted it the next day — incomplete analysis, image-builder in particular has a looser SecurityContext.
- **bpftrace/eBPF kill-on-socket-creation approach** (Paul Buckley's DaemonSet patch). Considered as the fastest weekend mitigation but superseded by Artsiom's modprobe-blacklist approach, which doesn't require killing live processes.
- **"We can't unload kernel modules in AWS."** Initial belief; reversed after Artsiom's research showed preventing module *load* (vs. unloading already-loaded ones) is feasible and sufficient since the modules weren't actually loaded in practice.
- **Sunday production rollout.** Original plan from the Saturday sync was Sunday MTS deploy. Reversed Sunday afternoon — no verified attack vector, deploy Monday with full engineering coverage instead.
- **AMI kernel patch as primary fix.** Initially on the table; demoted to a follow-up because module blacklisting is lower-risk to ship over a weekend.
