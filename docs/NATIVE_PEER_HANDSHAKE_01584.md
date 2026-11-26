# 0.15.84 — real peer handshake diagnostic

Device evidence from 0.15.83: repeated unique synthetic probe batches passed; independent queues each consumed three packets, four sockets protected, no duplicates or injection failures. Non-IPv4 traffic was rejected.

This increment imports exactly one peer per Exit A, Exit B and optional Home slot into the existing Android Keystore encrypted store in a separate debug package. Numeric IPv4/IPv6 endpoints only; no DNS resolution. The WireGuard canonical profile is reduced to handshake-only IPC fields, with ephemeral local UDP ports and a diagnostic five-second keepalive. No allowed IPs are installed in native peers, no application payload can be injected through their handles, no OS TUN/routes/DNS are created, and no real profile data is logged. Real peer verification requires new handshake timestamp and nonzero encrypted transfer counters for every selected session; four or six protected sockets, zero failures, stable physical network. Test automatically stops at 90 seconds, or on user stop, network change, revocation or failure.

Do not use simultaneously with existing root or Android VPN connections. Reimport profiles in this package; stable and old diagnostic installations remain untouched. This does NOT validate app routing, live payload forwarding, kill switch, DNS, or Moka authentication. Host tests validate IPC conversion and rejection; on-device remote handshakes remain necessary. A profile using hostname endpoints is intentionally refused until a controlled resolver is implemented.

## 0.15.85 profile audit
Device returned profile-validation/IllegalArgumentException before any native session. Exact cause unknown. Add fixed per-slot reason codes, encrypted-store error code, duplicate identity slot pair, and offline preflight button. No key, endpoint, or raw exception messages are printed. Duplicate identity remains refused. New debug package suffix native085; original release unchanged.

## 0.15.86 provider import
Home saves on device; both AirVPN profiles report generic native rejection. Exact rejected field is unknown. Return fixed reason codes for format, key, identity, allowed IP, port, PSK and endpoint failures. Recognize valid hostname profiles and save them locally, but never emit hostname IPC or perform DNS. Explicit temporary numeric IP override for hostname only preserves port and keys and is validated by Go before any session starts. Original config remains encrypted and unchanged. Provider-style synthetic IPv4/IPv6 and hostname regression cases added. No production routing.
