package com.yooshastan.wonheeproxy;

import com.wireguard.config.Config;
import com.wireguard.config.InetNetwork;
import com.wireguard.config.Peer;

import java.io.ByteArrayInputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Optional DNS addresses reachable through WireGuard. This changes only the
 * runtime configuration, not the imported profile. The app does not provide
 * DoH/DoQ or its own tracker blocking.
 */
final class VpnDnsOverride {
    private VpnDnsOverride() { }

    static Config prepare(Config original, boolean useHomeDns, String server) throws Exception {
        if (!useHomeDns) return original;
        String input = server == null ? "" : server.trim();
        String[] hosts = input.split(",", -1);
        if (hosts.length == 0 || hosts.length > 2) {
            throw new IllegalArgumentException("Enter one or two numeric DNS IP addresses.");
        }
        List<String> servers = new ArrayList<>();
        for (String item : hosts) {
            String host = item.trim();
            if (!isNumericIp(host)) {
                throw new IllegalArgumentException("DNS must contain one or two numeric IP addresses.");
            }
            final InetAddress target;
            try {
                // Only numeric syntax reaches this call; no hostname lookup is attempted.
                target = InetAddress.getByName(host);
            } catch (Exception invalid) {
                throw new IllegalArgumentException("DNS must contain valid IP addresses.");
            }
            if (target.isAnyLocalAddress() || target.isLoopbackAddress()
                    || target.isMulticastAddress() || target.isLinkLocalAddress()) {
                throw new IllegalArgumentException("Choose a reachable DNS server IP.");
            }
            if (!isRoutedInsideTunnel(original, target)) {
                throw new IllegalArgumentException("DNS address is outside WireGuard AllowedIPs.");
            }
            String canonicalHost = target.getHostAddress();
            if (servers.contains(canonicalHost)) {
                throw new IllegalArgumentException("Use two different DNS IP addresses.");
            }
            servers.add(canonicalHost);
        }
        String canonical = String.join(", ", servers);
        String source = original.toWgQuickString();
        StringBuilder modified = new StringBuilder(source.length() + 48);
        boolean inInterface = false;
        boolean handled = false;
        boolean foundInterface = false;

        for (String line : source.split("\\r?\\n", -1)) {
            String trimmed = line.trim();
            if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
                if (inInterface && !handled) {
                    modified.append("DNS = ").append(canonical).append('\n');
                    handled = true;
                }
                inInterface = "[Interface]".equalsIgnoreCase(trimmed);
                if (inInterface) foundInterface = true;
            }
            int equal = line.indexOf('=');
            if (inInterface && equal > 0
                    && "DNS".equalsIgnoreCase(line.substring(0, equal).trim())) {
                if (handled) throw new IllegalArgumentException("Duplicate DNS configuration.");
                modified.append("DNS = ").append(canonical).append('\n');
                handled = true;
            } else {
                modified.append(line).append('\n');
            }
        }
        if (!foundInterface) throw new IllegalArgumentException("WireGuard interface missing.");
        if (!handled) modified.append("DNS = ").append(canonical).append('\n');
        try {
            return Config.parse(new ByteArrayInputStream(
                    modified.toString().getBytes(StandardCharsets.UTF_8)));
        } catch (Exception invalid) {
            // Never expose a parser exception containing private WireGuard fields.
            throw new IllegalArgumentException("DNS override could not be applied.");
        }
    }

    static boolean hasDns(Config config) {
        if (config == null) return false;
        boolean inInterface = false;
        for (String line : config.toWgQuickString().split("\\r?\\n")) {
            String trimmed = line.trim();
            if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
                inInterface = "[Interface]".equalsIgnoreCase(trimmed);
            } else if (inInterface) {
                int equals = trimmed.indexOf('=');
                if (equals >= 0 && "DNS".equalsIgnoreCase(trimmed.substring(0, equals).trim())
                        && !trimmed.substring(equals + 1).trim().isEmpty()) return true;
            }
        }
        return false;
    }

    private static boolean isRoutedInsideTunnel(Config config, InetAddress target) {
        byte[] host = target.getAddress();
        for (Peer peer : config.getPeers()) {
            for (InetNetwork network : peer.getAllowedIps()) {
                byte[] subnet = network.getAddress().getAddress();
                if (subnet.length != host.length) continue;
                int bits = network.getMask();
                boolean inside = true;
                for (int i = 0; i < host.length; i++) {
                    int useBits = Math.min(8, Math.max(0, bits));
                    int mask = useBits == 0 ? 0 : (0xff << (8 - useBits)) & 0xff;
                    if (((host[i] & 0xff) & mask) != ((subnet[i] & 0xff) & mask)) {
                        inside = false;
                        break;
                    }
                    bits -= 8;
                }
                if (inside) return true;
            }
        }
        return false;
    }

    private static boolean isNumericIp(String host) {
        if (host.isEmpty() || host.length() > 45
                || host.indexOf('%') >= 0 || host.indexOf('/') >= 0) return false;
        if (host.indexOf(':') >= 0) {
            return host.matches("[0-9a-fA-F:.]+");
        }
        if (!host.matches("[0-9]+(\\.[0-9]+){3}")) return false;
        String[] octets = host.split("\\.");
        for (String octet : octets) {
            try {
                if (Integer.parseInt(octet) > 255) return false;
            } catch (NumberFormatException invalid) {
                return false;
            }
        }
        return true;
    }
}
