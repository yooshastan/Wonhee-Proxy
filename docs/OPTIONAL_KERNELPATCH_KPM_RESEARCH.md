# Optional Wonhee KernelPatch / KPM helper — feasibility and safety note

Status: DESIGN ONLY. Not a requirement of Batch E.1 or any shipping Wonhee APK.

## Motivation

Wonhee Proxy already uses WireGuard kernel interfaces, root route policies, and user-space encrypted DNS (DoH, DoQ, DoH3). APatch/Folkpatch can support KernelPatch Modules (KPMs), but vendor kernels, forks and patches differ. A KPM must never become a requirement for compatibility with generic WireGuard providers or self-hosted peers.

The bindhosts project is a precedent for a narrow optional hosts-file redirection KPM, not a general-purpose VPN firewall. Bindhosts documentation says its APatch hosts_file_redirect mode is hit-or-miss and does not coexist with AdAway in that mode. Standard hosts methods and netd/zygisk alternatives exist.

## Preferred sequence

1. Zero-change preflight on Pixel 8a: kernel version, available eBPF/cgroup hooks, netfilter functionality, APatch/Folkpatch KPM API level, ability to load/unload a test module, boot-image recovery method. No packet interception or kernel hooks in this phase.
2. Prefer upstream Linux cgroup/eBPF/tc/socket accounting when reliable and supported. Prefer Android netd/routing APIs for conventional traffic policy. Do not reimplement WireGuard cryptography or packet handling.
3. Optional KPM prototype must initially be a pure read-only diagnostic with counters only, no packet payload capture, no UID-to-domain history, no route/firewall modification and no blocking.
4. Only after extensive testing on an independent rescue path and device/kernel compatibility matrix should a separate and opt-in enforcement module be researched. Design for verified ownership, per-device feature negotiation, a safe unload path, and strict no-op fallback.
5. Real fail-closed guarantees require an independently tested all-packet policy, IPv6, dual-tunnel endpoint exemption, handoffs, boot/reboot, crash restoration, and rollback. KPM presence alone does not imply a kill switch.

## Explicit exclusions

- No kernel DNS blocklist parser: 250k-domain filtering and maintained lists stay in user space.
- No embedded KPM, patched boot image, KPM Load/Embed operations, SELinux weakening, broad netfilter bypass, or direct kernel memory hooks in this branch.
- No attempt to bypass apps' own HTTPS DoH, certificate pinning, or Android's security model as a filter strategy.
- No dependency on root for non-root compatible WireGuard provider modes.

## Suggested module boundaries

- Wonhee UI: single switch labeled Advanced kernel diagnostics (unsupported kernels display Unavailable).
- Policy daemon / userspace: verified configuration, safe updater, error handling and encrypted mesh coordination.
- Optional kernel component: restricted packet-path evidence counters only; explicit versioned control protocol with no secret keys or domain lists.
- Shared observation: human-readable status reports that distinguish inferred paths, observed counters, actual packet tests and strict enforcement.

## External references

- https://apatch.dev/kpm-usage-guide.html
- https://apatch.dev/what-is-apatch.html
- https://github.com/bindhosts/bindhosts/blob/master/Documentation/modes.md
- https://github.com/bindhosts/bindhosts/blob/master/Documentation/hiding.md

Do not install unreviewed KPM modules on the working Pixel 8a baseline; keep a known-good boot image and independent recovery path for any eventual experimental kernel tests.
