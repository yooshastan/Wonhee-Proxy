package com.yooshastan.wonheeproxy;

import java.util.List;

/** Parses the non-secret endpoint shape from `wg show IFACE endpoints`. */
final class RootWireGuardEndpoint {
    private RootWireGuardEndpoint() { }

    static boolean hasSingleNumericEndpoint(List<String> lines) {
        if (lines == null || lines.size() != 1 || lines.get(0) == null) return false;
        String[] fields = lines.get(0).trim().split("\\s+");
        if (fields.length != 2 || fields[0].isEmpty()) return false;
        String endpoint = fields[1];
        String host;
        String port;
        if (endpoint.startsWith("[")) {
            int close = endpoint.indexOf(']');
            if (close <= 1 || close + 2 >= endpoint.length()
                    || endpoint.charAt(close + 1) != ':') return false;
            host = endpoint.substring(1, close);
            port = endpoint.substring(close + 2);
            if (!host.contains(":")) return false;
            // The kernel exposes numeric endpoints, not DNS names.
            if (!host.matches("[0-9a-fA-F:.%]+")) return false;
        } else {
            int colon = endpoint.lastIndexOf(':');
            if (colon <= 0) return false;
            host = endpoint.substring(0, colon);
            port = endpoint.substring(colon + 1);
            String[] octets = host.split("\\.", -1);
            if (octets.length != 4) return false;
            for (String octet : octets) {
                if (!octet.matches("[0-9]{1,3}")) return false;
                if (Integer.parseInt(octet) > 255) return false;
            }
        }
        if (!port.matches("[0-9]{1,5}")) return false;
        int number = Integer.parseInt(port);
        return number > 0 && number <= 65535;
    }
}
