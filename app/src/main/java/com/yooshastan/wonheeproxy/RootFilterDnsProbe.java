package com.yooshastan.wonheeproxy;

import java.util.Arrays;

/**
 * Read-only, locally initiated DNS reply verifier for Batch E.2.
 * This is NOT a proof of system-wide DNS coverage or of why a resolver
 * returned NXDOMAIN: an upstream could also return NXDOMAIN.
 */
final class RootFilterDnsProbe {
    private RootFilterDnsProbe() { }

    static byte[] query(String domain, boolean ipv6, int id) {
        if (!RootTrackerPolicy.validDomain(domain)
                || domain.endsWith(".local") || domain.endsWith(".internal")
                || domain.endsWith(".arpa")) {
            throw new IllegalArgumentException("Only valid public-style domains may be tested.");
        }
        byte[] result = DoHWireMessage.question(domain, id);
        if (ipv6) {
            // DoHWireMessage emits type A (0x0001), class IN (0x0001).
            // Change QTYPE only; the DNS header and QNAME stay identical.
            result[result.length - 3] = 28; // AAAA (0x001c)
        }
        return result;
    }

    static boolean isExactLocalNxDomain(byte[] question, byte[] response) {
        if (question == null || response == null || question.length < 17
                || question.length != response.length) return false;
        if (!Arrays.equals(Arrays.copyOfRange(question, 0, 2),
                Arrays.copyOfRange(response, 0, 2))) return false;
        int flags = ((response[2] & 255) << 8) | (response[3] & 255);
        // QR, response code NXDOMAIN, no TC, no unexpected opcode.
        if ((flags & 0x8000) == 0 || (flags & 0x7800) != 0
                || (flags & 0x0200) != 0 || (flags & 0x000f) != 3) return false;
        // Exactly one question, no answer/authority/additional records.
        if ((response[4] & 255) != 0 || (response[5] & 255) != 1) return false;
        for (int i = 6; i <= 11; i++) {
            if (response[i] != 0) return false;
        }
        return Arrays.equals(Arrays.copyOfRange(question, 12, question.length),
                Arrays.copyOfRange(response, 12, response.length));
    }
}
