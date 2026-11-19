package com.yooshastan.wonheeproxy;

import java.util.List;

/**
 * Short, non-technical guidance for the guarded root Start preflight.
 *
 * The backend's read-only check is the authority. This class NEVER changes
 * routes, DNS, firewall, profiles or tunnel state. It only maps common
 * preflight blockers to a single next step without exposing raw root data.
 */
final class RootStartReadinessGuide {
    private RootStartReadinessGuide() { }

    static String message(boolean ready, String sanitizedReport, int connectNow,
            List<String> parked) {
        String report = sanitizedReport == null ? "" : sanitizedReport;
        if (ready) {
            String result = "Setup check passed for " + connectNow
                    + (connectNow == 1 ? " tunnel." : " compatible tunnels.")
                    + " You can return to Home and press Start. "
                    + "Actual Internet reachability and encrypted DNS "
                    + "have NOT been tested by this check.";
            if (parked != null && !parked.isEmpty()) {
                result += "\n\n" + parked.size() + " additional full-Internet "
                        + (parked.size() == 1 ? "profile stays" : "profiles stay")
                        + " selected but NOT connected. Routing different apps "
                        + "through those exits is not supported yet.";
            }
            return result;
        }
        String lower = report.toLowerCase(java.util.Locale.ROOT);
        String explanation;
        if (lower.contains("private dns")) {
            explanation = "Android Private DNS must remain OFF for this root "
                    + "connection mode. Wonhee handles encrypted DNS inside "
                    + "the selected tunnel.";
        } else if (lower.contains("owned dns") || lower.contains("dns ownership")
                || lower.contains("dns ownership ledger")
                || lower.contains("ownership ledger")) {
            explanation = "A previous DNS or firewall policy still has an "
                    + "ownership record. Use the independent H.2a audit before "
                    + "another Start. Do not delete or flush network rules.";
        } else if (lower.contains("reserved") || lower.contains("untracked")
                || lower.contains("firewall") || lower.contains("routing overrides")
                || lower.contains("guard")) {
            explanation = "Previously installed routing/firewall state needs "
                    + "review. Do not attempt to force a connection or "
                    + "remove rules manually.";
        } else if (lower.contains("running") || lower.contains("already up")
                || lower.contains("interface")) {
            explanation = "A tunnel or network interface is already present. "
                    + "Check its identity and use guarded Safe Stop rather "
                    + "than starting over it.";
        } else if (lower.contains("split-route") || lower.contains("home")
                || lower.contains("destinations") || lower.contains("overlap")) {
            explanation = "Choose one Internet exit and at least one "
                    + "compatible destination-specific tunnel. Check "
                    + "their effective WireGuard route labels on Home.";
        } else if (lower.contains("recovery")) {
            explanation = "Disable unattended root recovery after verifying "
                    + "the existing connection and rollback state.";
        } else if (lower.contains("root")) {
            explanation = "Wonhee could not verify root access or a required "
                    + "root component. Review root permission and diagnostics.";
        } else {
            explanation = "Wonhee could not prove that the current selection "
                    + "is safe to start. Review the connection diagnostics.";
        }
        return "Setup check failed BEFORE connecting any tunnels.\n\n"
                + explanation + "\n\n"
                + "No connection or routing change was requested by this check.";
    }
}
