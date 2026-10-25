package com.yooshastan.wonheeproxy;

import com.wireguard.config.Config;

import java.io.ByteArrayInputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;

/**
 * Optional plain DNS forwarding to a trusted server reachable inside WireGuard.
 * This changes only the connection-time configuration. It is NOT a DoH/DoQ
 * client and does not perform filtering; those require trusted gateway services.
 */
final class VpnDnsOverride {
    private VpnDnsOverride() { }

    static Config prepare(Config original, boolean useHomeDns, String server) throws Exception {
        if (!useHomeDns) return original;
        String host = server == null ? "" : server.trim();
        if (!isNumericIp(host)) {
            throw new IllegalArgumentException("Enter one numeric home DNS IP address.");
        }
        // Java resolution is safe here because numeric syntax is enforced first.
        final InetAddress target;
        try {
            target = InetAddress.getByName(host);
        } catch (Exception invalid) {
            throw new IllegalArgumentException("Home DNS must be a valid IP address.");
        }
        if (target.isAnyLocalAddress() || target.isLoopbackAddress()
                || target.isMulticastAddress() || target.isLinkLocalAddress()) {
            throw new IllegalArgumentException("Choose a reachable home DNS server IP.");
        }
        String canonical = target.getHostAddress();
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
