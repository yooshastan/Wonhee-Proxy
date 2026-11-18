package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Turns a set of selected profiles into a truthful, safe root Start plan.
 *
 * Root's existing routing backend can start one unrestricted IPv4/IPv6
 * Internet exit alongside non-overlapping destination-specific tunnels.
 * Additional full Internet exits may be selected as future alternatives, but
 * MUST NOT be started or advertised as connected until UID policy routing,
 * encrypted DNS and fail-closed enforcement have been verified on device.
 *
 * This class is PURE: it cannot start WireGuard, change a profile, or install
 * routes, DNS, firewall or system VPN settings.
 */
final class RootTunnelStartSelection {
    static final class Review {
        final boolean ready;
        final boolean needsPrimaryChoice;
        final String primary;
        final String message;
        final List<String> active;
        final List<String> parked;
        final List<String> primaryChoices;

        Review(boolean ready, boolean needsPrimaryChoice, String primary,
                String message, List<String> active, List<String> parked,
                List<String> primaryChoices) {
            this.ready = ready;
            this.needsPrimaryChoice = needsPrimaryChoice;
            this.primary = primary;
            this.message = message;
            this.active = Collections.unmodifiableList(new ArrayList<>(active));
            this.parked = Collections.unmodifiableList(new ArrayList<>(parked));
            this.primaryChoices = Collections.unmodifiableList(new ArrayList<>(primaryChoices));
        }
    }

    private RootTunnelStartSelection() { }

    static Review review(List<RootMultiTunnelPlan.Entry> selected,
            String requestedPrimary) {
        if (selected == null || selected.isEmpty()) {
            return refused("Choose your Internet exit and the tunnels you want to use.");
        }
        if (selected.size() > RootMultiTunnelPlan.MAX_TUNNELS) {
            return refused("Up to eight profiles can be selected.");
        }
        Set<String> seen = new HashSet<>();
        List<String> defaults = new ArrayList<>();
        List<RootMultiTunnelPlan.Entry> split = new ArrayList<>();
        for (RootMultiTunnelPlan.Entry entry : selected) {
            if (entry == null || entry.name == null
                    || !seen.add(entry.name.toLowerCase(java.util.Locale.ROOT))) {
                return refused("Selected tunnels need distinct saved identities.");
            }
            boolean ipv4 = false, ipv6 = false;
            for (String destination : entry.peerRoutes) {
                if ("0.0.0.0/0".equals(destination)) ipv4 = true;
                if ("::/0".equals(destination)
                        || "0:0:0:0:0:0:0:0/0".equals(destination)) ipv6 = true;
            }
            if (ipv4 != ipv6) {
                return refused(entry.name + " is missing either IPv4 or IPv6 "
                        + "Internet coverage. Edit its routes before Start.");
            }
            if (ipv4) defaults.add(entry.name);
            else split.add(entry);
        }
        if (defaults.isEmpty()) {
            return refused("Choose one IPv4+IPv6 Internet exit. Other selected "
                    + "tunnels can handle specific destinations.");
        }
        if (defaults.size() > 1
                && (requestedPrimary == null || !defaults.contains(requestedPrimary))) {
            return new Review(false, true, "", "Choose one primary Internet exit. "
                    + "The other full-exit profiles will stay selected as available "
                    + "alternatives but will NOT connect in this session. "
                    + "Non-overlapping destination tunnels can connect alongside "
                    + "your primary exit.", Collections.emptyList(),
                    Collections.emptyList(), defaults);
        }
        String primary = defaults.size() == 1 ? defaults.get(0) : requestedPrimary;
        List<RootMultiTunnelPlan.Entry> activeEntries = new ArrayList<>();
        List<String> activeNames = new ArrayList<>();
        List<String> parkedNames = new ArrayList<>();
        // Preserve the original selection order for the connection lifecycle.
        for (RootMultiTunnelPlan.Entry entry : selected) {
            if (defaults.contains(entry.name) && !entry.name.equals(primary)) {
                parkedNames.add(entry.name);
            } else {
                activeEntries.add(entry);
                activeNames.add(entry.name);
            }
        }
        // Do NOT relax the real cross-route validator or the root startup
        // preflight. Only candidate active profiles are passed to the backend.
        RootTunnelSelectionAdvisor.Review verified =
                RootTunnelSelectionAdvisor.review(activeEntries);
        if (!verified.ready) {
            return new Review(false, false, primary, verified.message,
                    Collections.emptyList(), parkedNames, defaults);
        }
        String message = activeEntries.size() + " tunnel"
                + (activeEntries.size() == 1 ? "" : "s")
                + " ready for guarded Start. Primary: " + primary
                + ". Destination-specific: " + verified.splitTunnelCount + ".";
        if (!parkedNames.isEmpty()) {
            message += " " + parkedNames.size() + " additional Internet exit"
                    + (parkedNames.size() == 1 ? "" : "s")
                    + " selected but NOT connected (app-specific multi-exit "
                    + "enforcement is not available yet).";
        }
        return new Review(true, false, primary, message, activeNames,
                parkedNames, defaults);
    }

    private static Review refused(String message) {
        return new Review(false, false, "", message,
                Collections.emptyList(), Collections.emptyList(),
                Collections.emptyList());
    }
}
