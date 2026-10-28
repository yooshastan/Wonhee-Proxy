package com.yooshastan.wonheeproxy;

/**
 * Strict numeric RFC1918 IPv4 + TCP port validation for a single user-approved
 * home-service probe. Never resolves a hostname or accepts public destinations.
 */
final class PrivateIpv4Target {
    final int port;
    private final byte[] ipv4;

    private PrivateIpv4Target(byte[] ipv4, int port) {
        this.ipv4 = ipv4.clone();
        this.port = port;
    }

    static PrivateIpv4Target parse(String inputIp, String inputPort) {
        if (inputIp == null || inputPort == null) throw invalid();
        String ip = inputIp.trim();
        String portValue = inputPort.trim();
        if (ip.length() < 7 || ip.length() > 15 || !ip.matches("[0-9.]+")
                || portValue.isEmpty() || portValue.length() > 5
                || !portValue.matches("[0-9]+")) throw invalid();

        String[] parts = ip.split("\\.", -1);
        if (parts.length != 4) throw invalid();
        byte[] address = new byte[4];
        int[] octets = new int[4];
        try {
            for (int i = 0; i < 4; i++) {
                String value = parts[i];
                if (value.isEmpty() || value.length() > 3
                        || (value.length() > 1 && value.startsWith("0"))) throw invalid();
                int octet = Integer.parseInt(value);
                if (octet < 0 || octet > 255) throw invalid();
                octets[i] = octet;
                address[i] = (byte) octet;
            }
            int port = Integer.parseInt(portValue);
            if (port < 1 || port > 65535) throw invalid();
            boolean rfc1918 = octets[0] == 10
                    || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
                    || (octets[0] == 192 && octets[1] == 168);
            if (!rfc1918) throw invalid();
            return new PrivateIpv4Target(address, port);
        } catch (NumberFormatException invalidNumber) {
            throw invalid();
        }
    }

    byte[] addressBytes() {
        return ipv4.clone();
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException(
                "Enter a numeric private IPv4 address (10.x, 172.16–31.x, or 192.168.x) "
                        + "and TCP port 1–65535.");
    }
}
