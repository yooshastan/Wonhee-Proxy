# Wonhee immutable Product Batch A–I roadmap

This is the **product delivery sequence**. Older developer diagnostics
that happened to be labeled "Batch C", "Batch D" or "Batch E" are evidence
tools, not replacements for the corresponding product features.

| Product batch | Scope | Current position |
| --- | --- | --- |
| A | Root kernel WireGuard multi-tunnel session | Implemented; ongoing device regression |
| B | Home split routes + independent Internet tunnel selection | Implemented; rollback ownership verified |
| C | Identity-verified reconnect and user-controlled recovery | Opt-in implementation; separate background safeguards |
| D | Root-bound DoH/DoQ/DoH3 and explicit system DNS-port interception | 0.15.4 alpha; Android interception and rollback observed; broader leak/reboot tests remain |
| E | Optional local DNS tracker blocklist and allowlist | 0.15.5 alpha; device tests pending |
| F | Fail-closed **all-traffic** kill-switch prototype | Not implemented |
| G | Background policy monitoring/recovery automation | Not implemented |
| H | Integrated privacy/control UI and simplified guided prompts | Not implemented (existing guided UI is incremental groundwork) |
| I | Beta stabilization, compatibility, packaging and security validation | Not implemented |

**Post-I backlog:** Moka's simultaneous-root-tunnel/Navidrome compatibility
regression, unless the user explicitly changes this ordering.

All product batches are gated by safe, device-verified behavior; CI-only
compilation does not establish network security or leak freedom. Components
remain opt-in until protection, rollback and compatibility are demonstrated.
