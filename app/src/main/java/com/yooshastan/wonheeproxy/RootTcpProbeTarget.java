package com.yooshastan.wonheeproxy;

import java.net.InetAddress;

/** A numeric destination only: the diagnostic must not silently perform DNS. */
final class RootTcpProbeTarget {
    final String address;
    final int port;
    final int family;

    private RootTcpProbeTarget(String address, int port, int family) {
        this.address = address;
        this.port = port;
        this.family = family;
    }

    static RootTcpProbeTarget parse(String input) {
        if (input == null) throw new IllegalArgumentException("Enter a numeric IP and TCP port.");
        String text = input.trim();
        String address;
        String portText;
        int family;
        if (text.startsWith("[")) {
            int closing = text.indexOf(']');
            if (closing < 0 || closing + 1 >= text.length() || text.charAt(closing + 1) != ':') {
                throw new IllegalArgumentException("Use [IPv6]:port for IPv6 destinations.");
            }
            address = text.substring(1, closing);
            portText = text.substring(closing + 2);
            family = 6;
            if (!address.contains(":") || !address.matches("[0-9a-fA-F:.]+")) {
                throw new IllegalArgumentException("Use a numeric IPv6 address; no hostnames or scopes.");
            }
        } else {
            int separator = text.lastIndexOf(':');
            if (separator <= 0 || separator != text.indexOf(':')) {
                throw new IllegalArgumentException("Use IPv4:port or [IPv6]:port.");
            }
            address = text.substring(0, separator);
            portText = text.substring(separator + 1);
            family = 4;
            if (!address.matches("[0-9]{1,3}(\\.[0-9]{1,3}){3}")) {
                throw new IllegalArgumentException("Use a numeric IPv4 address; no hostnames.");
            }
            for (String octet : address.split("\\.")) {
                if (Integer.parseInt(octet) > 255) {
                    throw new IllegalArgumentException("IPv4 octets must be 0–255.");
                }
            }
        }
        if (!portText.matches("[0-9]{1,5}")) {
            throw new IllegalArgumentException("TCP port must be between 1 and 65535.");
        }
        int port = Integer.parseInt(portText);
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("TCP port must be between 1 and 65535.");
        }
        try {
            if (InetAddress.getByName(address).getAddress().length != (family == 4 ? 4 : 16)) {
                throw new IllegalArgumentException("IP address family does not match the target.");
            }
        } catch (IllegalArgumentException invalid) {
            throw invalid;
        } catch (Exception invalid) {
            throw new IllegalArgumentException("Enter a valid numeric IP address.");
        }
        return new RootTcpProbeTarget(address, port, family);
    }

    String label() {
        return family == 6 ? "[" + address + "]:" + port : address + ":" + port;
    }
}
