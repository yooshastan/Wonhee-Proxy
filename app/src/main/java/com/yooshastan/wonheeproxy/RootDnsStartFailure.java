package com.yooshastan.wonheeproxy;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Fail-closed rendering of the non-secret DNS startup phase. Never replay raw
 * shell errors, user-entered resolver URLs, bootstrap addresses, profile names,
 * private keys or stack traces into the saved crash report / status screen.
 */
final class RootDnsStartFailure {
    private static final Pattern PHASE = Pattern.compile(
            "\\[(POLICY_PREFLIGHT|DNS_POLICY_PARSE|PROFILE_VALIDATION|TUNNEL_IDENTITY"
            + "|UPSTREAM_ROUTE|FIREWALL_COLLISION_PREFLIGHT|RELAY_PORT_PREFLIGHT"
            + "|RELAY_PREPARE|RELAY_LAUNCH|PROCESS_IDENTITY|LOCAL_LISTENER"
            + "|LOCAL_DNS_HEALTH|LOCAL_DNS_TIMEOUT|LOCAL_TRACKER_HEALTH"
            + "|LOCAL_TRACKER_TIMEOUT|OWNERSHIP_LEDGER_COMMIT|FIREWALL_INSTALL"
            + "|FIREWALL_VERIFY)\\]");
    private RootDnsStartFailure() { }

    static String summary(String rawReport) {
        // Whitelisted phase only, regardless of the remaining error content.
        Matcher match = PHASE.matcher(rawReport == null ? "" : rawReport);
        String phase = match.find() ? match.group(1) : "UNSPECIFIED";
        String recommendation;
        switch (phase) {
            case "POLICY_PREFLIGHT":
                recommendation = "Check Android Private DNS is OFF, unattended recovery "
                        + "disabled, and no existing DNS/guard ownership is recorded.";
                break;
            case "UPSTREAM_ROUTE":
                recommendation = "Chosen DNS bootstrap does not match the selected "
                        + "upstream tunnel's root route. Review DNS tunnel selection "
                        + "and routing without disabling the DNS safety gate.";
                break;
            case "TUNNEL_IDENTITY":
                recommendation = "One selected WireGuard tunnel or its public identity "
                        + "was not verified UP. Inspect both tunnel states.";
                break;
            case "RELAY_PORT_PREFLIGHT":
            case "LOCAL_LISTENER":
                recommendation = "Local DNS port 53535 was not available or did not "
                        + "become ready. Run the read-only DNS listener audit.";
                break;
            case "RELAY_PREPARE":
            case "RELAY_LAUNCH":
            case "PROCESS_IDENTITY":
                recommendation = "The owned DNS relay could not prepare, launch or "
                        + "verify its process. Check root tools and relay lifecycle.";
                break;
            case "LOCAL_DNS_HEALTH":
                recommendation = "The local relay did not produce a verified A answer "
                        + "for its upstream health probe. Check the selected "
                        + "WireGuard DNS path and encrypted resolver without "
                        + "disabling the DNS safety gate.";
                break;
            case "LOCAL_DNS_TIMEOUT":
                recommendation = "The relay's upstream DNS health query received "
                        + "no reply within nine seconds. This does not distinguish "
                        + "a slow encrypted upstream from a delayed local relay. "
                        + "No direct/plaintext fallback was attempted.";
                break;
            case "LOCAL_TRACKER_HEALTH":
                recommendation = "The upstream A-answer check passed, but the "
                        + "separate tracker-block health query did not return "
                        + "the expected local NXDOMAIN. Review loaded tracker "
                        + "rules; do not disable blocking to force a startup.";
                break;
            case "LOCAL_TRACKER_TIMEOUT":
                recommendation = "The upstream A-answer check passed, but the "
                        + "tracker-block health query received no reply within "
                        + "nine seconds. Inspect the local relay and tracker "
                        + "policy before another start.";
                break;
            case "FIREWALL_COLLISION_PREFLIGHT":
            case "FIREWALL_INSTALL":
            case "FIREWALL_VERIFY":
                recommendation = "The exact owned DNS firewall preflight or rule "
                        + "verification failed. Do not flush firewall rules.";
                break;
            case "OWNERSHIP_LEDGER_COMMIT":
                recommendation = "The saved DNS rollback ownership record could "
                        + "not be verified. Inspect lifecycle ownership.";
                break;
            case "DNS_POLICY_PARSE":
            case "PROFILE_VALIDATION":
                recommendation = "Review the selected encrypted resolver, profile "
                        + "configuration and tracker list. No plaintext fallback.";
                break;
            default:
                recommendation = "Original DNS substage was unavailable in this "
                        + "report. The exact cause has not been identified.";
        }
        return "DNS activation phase: " + phase + "\n"
                + recommendation + "\n"
                + "This describes a startup stage, not proof of the underlying "
                + "network failure. Raw resolver and peer details are intentionally hidden.";
    }
}
