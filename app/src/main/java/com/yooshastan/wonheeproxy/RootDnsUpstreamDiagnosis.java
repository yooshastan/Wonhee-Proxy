package com.yooshastan.wonheeproxy;

import java.util.List;

/**
 * Sanitizes one-shot, root-bound encrypted DNS probe output.
 *
 * No raw resolver URLs, hostnames, bootstrap IPs, queried domains, shell error
 * messages, or peer data ever leave this classifier. Unknown responses are
 * refused; there is no fallback transport or alternate network interface.
 *
 * This does not diagnose local relay IPC; it only verifies the bound upstream.
 */
final class RootDnsUpstreamDiagnosis {
    static final String VERIFIED = "VERIFIED";
    static final String INTERFACE = "UPSTREAM_INTERFACE_UNAVAILABLE";
    static final String BIND = "UPSTREAM_BIND_FAILED";
    static final String CONNECT = "UPSTREAM_CONNECT_TLS";
    static final String HTTP = "UPSTREAM_HTTP_INVALID";
    static final String DNS_REPLY = "UPSTREAM_REPLY_INVALID";
    static final String UNAVAILABLE = "UPSTREAM_PROBE_UNAVAILABLE";

    private RootDnsUpstreamDiagnosis() { }

    static String classify(int exitCode, List<String> lines) {
        if (lines == null || lines.size() != 1) return UNAVAILABLE;
        String response = lines.get(0);
        if (response == null) return UNAVAILABLE;
        String line = response.trim();
        if (exitCode == 0 && line.matches("VERIFIED A_COUNT=[1-9][0-9]{0,2}")) {
            return VERIFIED;
        }
        if (exitCode == 0 || !line.matches("REFUSED [A-Z_]{3,40}")) {
            return UNAVAILABLE;
        }
        switch (line.substring("REFUSED ".length())) {
            case "INTERFACE_UNAVAILABLE": return INTERFACE;
            case "BIND_FAILED": return BIND;
            case "TLS_OR_CONNECT_FAILED": return CONNECT;
            case "HTTP_NOT_200":
            case "WRONG_CONTENT_TYPE": return HTTP;
            case "DNS_REPLY_INVALID":
            case "DNS_REPLY_TOO_LARGE": return DNS_REPLY;
            default: return UNAVAILABLE;
        }
    }
}
