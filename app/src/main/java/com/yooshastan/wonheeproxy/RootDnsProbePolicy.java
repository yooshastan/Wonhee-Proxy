package com.yooshastan.wonheeproxy;

import java.net.URI;
import java.util.Locale;

/**
 * Validates a single strict, root-bound encrypted DNS probe. This policy does
 * not authorize changes to Android DNS, firewall rules or WireGuard profiles.
 */
final class RootDnsProbePolicy {
    final String protocol;
    final String url;
    final String hostname;
    final String bootstrapAddress;
    final int port;
    final int family;

    private RootDnsProbePolicy(String protocol, String url, String hostname,
                               String bootstrapAddress, int port, int family) {
        this.protocol = protocol;
        this.url = url;
        this.hostname = hostname;
        this.bootstrapAddress = bootstrapAddress;
        this.port = port;
        this.family = family;
    }

    static RootDnsProbePolicy parse(String protocol, String url, String bootstrap) {
        if ("doh".equals(protocol) || "doh3".equals(protocol)) {
            DoHProbePolicy checked = DoHProbePolicy.parse(url, bootstrap);
            return new RootDnsProbePolicy(protocol, checked.url, checked.hostname,
                    checked.bootstrapAddress, checked.port, checked.family);
        }
        if (!"doq".equals(protocol)) {
            throw new IllegalArgumentException("Choose DoH, DoQ or DoH3 explicitly.");
        }
        if (url == null || bootstrap == null) {
            throw new IllegalArgumentException("Specify a DoQ server and numeric bootstrap IP.");
        }
        String bootstrapIp = bootstrap.trim();
        RootTcpProbeTarget numeric = RootTcpProbeTarget.parse(bootstrapIp.contains(":")
                ? "[" + bootstrapIp + "]:853" : bootstrapIp + ":853");
        String source = url.trim();
        if (source.length() > 2048 || source.length() < 10) {
            throw new IllegalArgumentException("DoQ endpoint length invalid.");
        }
        URI uri;
        try { uri = URI.create(source); }
        catch (IllegalArgumentException invalid) {
            throw new IllegalArgumentException("Enter a valid quic://hostname[:port] endpoint.");
        }
        if (!"quic".equals(uri.getScheme()) || uri.isOpaque()
                || uri.getRawUserInfo() != null || uri.getRawQuery() != null
                || uri.getRawFragment() != null || uri.getHost() == null
                || (uri.getRawPath() != null && !uri.getRawPath().isEmpty())) {
            throw new IllegalArgumentException("DoQ requires quic://hostname[:port], without path or credentials.");
        }
        String host = uri.getHost().toLowerCase(Locale.ROOT);
        if (host.length() > 253 || !host.contains(".") || !host.matches("[a-z0-9.-]+")) {
            throw new IllegalArgumentException("DoQ requires a valid DNS hostname.");
        }
        for (String label : host.split("\\.", -1)) {
            if (label.isEmpty() || label.length() > 63 || label.startsWith("-")
                    || label.endsWith("-")) {
                throw new IllegalArgumentException("DoQ server contains an invalid DNS label.");
            }
        }
        int port = uri.getPort() == -1 ? 853 : uri.getPort();
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("DoQ TLS port must be 1–65535.");
        }
        return new RootDnsProbePolicy(protocol, uri.toASCIIString(), host,
                numeric.address, port, numeric.family);
    }
}
