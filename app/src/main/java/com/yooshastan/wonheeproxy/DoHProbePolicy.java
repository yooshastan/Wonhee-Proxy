package com.yooshastan.wonheeproxy;

import java.net.URI;
import java.util.Locale;

/**
 * Strict, no-bootstrap-DNS configuration for Product D's *probe*. This does not
 * alter Android's resolver, WireGuard profiles, or the device's DNS routing.
 */
final class DoHProbePolicy {
    final String url;
    final String hostname;
    final String bootstrapAddress;
    final int port;
    final int family;

    private DoHProbePolicy(String url, String hostname, String bootstrapAddress,
                           int port, int family) {
        this.url = url;
        this.hostname = hostname;
        this.bootstrapAddress = bootstrapAddress;
        this.port = port;
        this.family = family;
    }

    static DoHProbePolicy parse(String inputUrl, String inputBootstrap) {
        if (inputUrl == null || inputBootstrap == null) {
            throw new IllegalArgumentException("Specify an HTTPS DoH URL and a numeric bootstrap IP.");
        }
        String address = inputBootstrap.trim();
        RootTcpProbeTarget numeric = RootTcpProbeTarget.parse(address.contains(":")
                ? "[" + address + "]:443" : address + ":443");

        String source = inputUrl.trim();
        if (source.length() > 2048) {
            throw new IllegalArgumentException("DoH endpoint URL is too long.");
        }
        URI uri;
        try { uri = URI.create(source); }
        catch (IllegalArgumentException invalid) {
            throw new IllegalArgumentException("Enter a valid HTTPS DoH endpoint URL.");
        }
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.isOpaque()
                || uri.getRawUserInfo() != null || uri.getRawQuery() != null
                || uri.getRawFragment() != null || uri.getHost() == null
                || uri.getHost().isEmpty()) {
            throw new IllegalArgumentException("Use HTTPS with a hostname/path; no credentials, query or fragment.");
        }
        String host = uri.getHost().toLowerCase(Locale.ROOT);
        if (host.length() > 253 || !host.contains(".") || !host.matches("[a-z0-9.-]+")) {
            throw new IllegalArgumentException("DoH endpoint requires a valid DNS hostname.");
        }
        for (String label : host.split("\\.", -1)) {
            if (label.isEmpty() || label.length() > 63 || label.startsWith("-")
                    || label.endsWith("-")) {
                throw new IllegalArgumentException("DoH endpoint requires valid DNS labels.");
            }
        }
        int port = uri.getPort() == -1 ? 443 : uri.getPort();
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("DoH TLS port must be 1–65535.");
        }
        String path = uri.getRawPath();
        if (path == null || !path.startsWith("/") || path.length() < 2) {
            throw new IllegalArgumentException("DoH endpoint requires an HTTPS path, e.g. /dns-query.");
        }
        return new DoHProbePolicy(uri.toASCIIString(), host, numeric.address,
                port, numeric.family);
    }

    static boolean approvedTunnel(boolean selected, boolean identityVerified,
                                  boolean ownedRulesVerified, String expectedDevice,
                                  String rootRouteDevice, String androidNetworkDevice) {
        return selected && identityVerified && ownedRulesVerified && expectedDevice != null
                && !expectedDevice.isEmpty() && expectedDevice.equals(rootRouteDevice)
                && expectedDevice.equals(androidNetworkDevice);
    }
}
