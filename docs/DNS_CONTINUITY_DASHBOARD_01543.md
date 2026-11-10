# Wonhee 0.15.43 — DNS continuity dashboard

## Based on Pixel 8a 0.15.42 evidence
On-device dashboard displayed two verified tunnels and a locally verified relay, with an observed snapshot of 265 DNS requests received, 184 forwarded, 80 blocked and 1 failed. The user successfully saved a local DNS aggregate baseline.

## Changes
- DNS tab shows the existing aggregate-only baseline comparison immediately after activity counters rather than burying it in longer verification instructions.
- A relay-scoped percentage shows `blocked / received` only if the relay identity is verified, tracker filtering enabled, counters available, and received > 0. No percentage is shown for an unknown/off relay.
- Activity explicitly notes that a baseline is an opt-in comparison, not continuous monitoring or leak protection.
- Existing manual baseline capture/clear controls remain; remove duplicate baseline detail text from the lengthy DNS coverage section.

## Safety
This PR changes only UI presentation. No DNS relay, routing, firewall, tracker policy, VPN, root operations, packet capture, RCS, or Wi-Fi Calling changes. Kill switch activation remains safety-paused, and Android Private DNS stays OFF on the Pixel 8a test device.

## Acceptance
- Android and native CI pass on final commit.
- Confirm relay-only percentage, including 0/0 no percentage, unknown relay, and disabled filtering.
- Confirm saved baseline comparison appears and its message changes with relay PID/count resets; this is not uptime proof.
- Confirm existing DNS lifetime counters, dashboard speed notification and both tunnels unaffected.
- Use original release keystore only after H.1 Safe Stop and H.2a CLEAN_STOPPED for local signed update; PR debug artifacts are not official.
