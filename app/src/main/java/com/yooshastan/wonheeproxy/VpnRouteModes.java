package com.yooshastan.wonheeproxy;

import com.wireguard.config.Config;
import com.wireguard.config.InetNetwork;
import com.wireguard.config.Peer;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Alpha 0.6 connection-time routing choices. Neither mode mutates the imported
 * configuration or its encrypted saved copy; WireGuard re-parses a temporary
 * wg-quick serialization before the session starts.
 */
final class VpnRouteModes {
    static final int PROFILE = 0;
    static final int HOME = 1;
    static final int ALL = 2;
    private static final int MAX_ROUTES = 16;
    private static final int MAX_TEXT = 512;

    private VpnRouteModes() { }

    static String suggestedHomeRoutes(Config config) {
        if (config == null || config.getPeers().size() != 1) return "";
        List<String> routes = new ArrayList<>();
        for (InetNetwork network : config.getPeers().get(0).getAllowedIps()) {
            String value = network.toString();
            if (!isDefaultRoute(value) && routes.size() < MAX_ROUTES) {
                routes.add(value);
            }
        }
        return String.join(", ", routes);
    }

    static String summary(Config config, int mode, String homeRoutes) {
        if (config == null) return "Import or choose a WireGuard profile.";
        if (mode == HOME) {
            String routes = homeRoutes == null ? "" : homeRoutes.trim();
            return "Home access: only the listed destinations enter WireGuard. "
                    + "Other internet traffic uses the phone's normal network. Routes: "
                    + (routes.isEmpty() ? "ENTER YOUR HOME CIDRs" : routes);
        }
        if (mode == ALL) {
            return "EXPERIMENTAL: request IPv4 + IPv6 default routes through home. "
                    + "Fedora forwarding, IPv4 NAT, IPv6 routing and DNS are NOT verified. "
                    + "The internet may stop working; no leak or kill-switch protection is proven.";
        }
        boolean v4 = false, v6 = false;
        for (Peer peer : config.getPeers()) {
            for (InetNetwork network : peer.getAllowedIps()) {
                String route = network.toString();
                if (route.equals("0.0.0.0/0")) v4 = true;
                if (route.equals("::/0") || route.equals("0:0:0:0:0:0:0:0/0")) v6 = true;
            }
        }
        if (v4 && v6) {
            return "Profile routes: IPv4 + IPv6 defaults requested. "
                    + "Gateway and leak safety are unverified.";
        }
        if (v4 || v6) {
            return "Profile routes: only one IP family has a default route. "
                    + "The other family may bypass the VPN.";
        }
        return "Profile routes: split tunnel. Other internet traffic may bypass the VPN.";
    }

    static Config prepare(Config original, int mode, String customRoutes) throws Exception {
        if (original == null) throw new IllegalArgumentException("Import a profile first.");
        if (mode == PROFILE) return original;
        if (mode != HOME && mode != ALL) {
            throw new IllegalArgumentException("Choose a valid routing mode.");
        }
        if (original.getPeers().size() != 1) {
            throw new IllegalArgumentException(
                    "Custom routing currently supports exactly one WireGuard peer. "
                            + "Use Profile routes for multi-peer configurations.");
        }
        final String allowed;
        if (mode == ALL) {
            allowed = "0.0.0.0/0, ::/0";
        } else {
            if (customRoutes == null || customRoutes.length() > MAX_TEXT) {
                throw new IllegalArgumentException("Home routes exceed 512 characters.");
            }
            String[] pieces = customRoutes.split(",", -1);
            if (pieces.length == 0 || pieces.length > MAX_ROUTES) {
                throw new IllegalArgumentException("Specify 1–16 home CIDRs separated by commas.");
            }
            List<String> routes = new ArrayList<>();
            for (String piece : pieces) {
                String route = piece.trim();
                if (route.isEmpty() || route.indexOf('/') < 1
                        || route.indexOf('\n') >= 0 || route.indexOf('\r') >= 0) {
                    throw new IllegalArgumentException("Home routes must be CIDRs such as 10.77.0.0/24.");
                }
                if (route.endsWith("/0")) {
                    throw new IllegalArgumentException(
                            "Home mode cannot use /0. Select All traffic to test default routing.");
                }
                routes.add(route);
            }
            allowed = String.join(", ", routes);
        }

        String source = original.toWgQuickString();
        StringBuilder rewritten = new StringBuilder(source.length() + allowed.length() + 32);
        boolean peerSection = false;
        boolean replaced = false;
        for (String line : source.split("\\r?\\n", -1)) {
            String field = line.trim();
            if (field.startsWith("[") && field.endsWith("]")) {
                peerSection = "[Peer]".equalsIgnoreCase(field);
            }
            int equals = line.indexOf('=');
            if (peerSection && equals > 0
                    && "AllowedIPs".equalsIgnoreCase(line.substring(0, equals).trim())) {
                if (replaced) throw new IllegalArgumentException("Duplicate AllowedIPs fields.");
                rewritten.append("AllowedIPs = ").append(allowed).append('\n');
                replaced = true;
            } else {
                rewritten.append(line).append('\n');
            }
        }
        if (!replaced) {
            // WireGuard's canonical peer serializer normally includes this field.
            // Reject missing fields instead of silently putting it in a wrong section.
            throw new IllegalArgumentException("Profile peer has no AllowedIPs field.");
        }
        final Config result;
        try {
            result = Config.parse(new ByteArrayInputStream(
                    rewritten.toString().getBytes(StandardCharsets.UTF_8)));
        } catch (Exception invalid) {
            // Parser errors might contain configuration fields. Do not expose secrets.
            throw new IllegalArgumentException("The selected routing CIDRs are invalid.");
        }
        if (result.getPeers().size() != 1) {
            throw new IllegalArgumentException("Failed to prepare single-peer routing.");
        }
        return result;
    }

    private static boolean isDefaultRoute(String route) {
        return route.equals("0.0.0.0/0") || route.equals("::/0")
                || route.equals("0:0:0:0:0:0:0:0/0");
    }
}
