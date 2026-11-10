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
            + "|LOCAL_DNS_HEALTH|OWNERSHIP_LEDGER_COMMIT|FIREWALL_INSTALL"
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
                recommendation = "The relay started but its own DNS/tracker test did "
                        + "not pass. Verify upstream connectivity and DNS configuration.";
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
