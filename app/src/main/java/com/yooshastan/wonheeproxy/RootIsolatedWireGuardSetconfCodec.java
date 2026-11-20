package com.yooshastan.wonheeproxy;

import java.util.HashSet;
import java.util.Set;

/**
 * Pure, fail-closed conversion of a Config.toWgQuickString() canonical
 * WireGuard profile into wg(8) setconf syntax.
 *
 * wg-quick is deliberately NOT invoked. It is a userspace shell script
 * that can have Android-specific assumptions and manipulate routes/DNS
 * when used incorrectly. This codec never emits Address, DNS, MTU,
 * Table, app selectors, scripts, firewall statements or socket marks.
 *
 * Input MUST be WireGuard-library-parsed and canonicalized text; never
 * pass arbitrary raw untrusted configuration text to this codec.
 */
final class RootIsolatedWireGuardSetconfCodec {
    private RootIsolatedWireGuardSetconfCodec() { }

    static String stripCanonicalQuick(String canonical) {
        if (canonical == null || canonical.length() < 32
                || canonical.length() > 32768) {
            throw new IllegalArgumentException("Invalid canonical WG profile length.");
        }
        final StringBuilder output = new StringBuilder();
        String section = "";
        boolean interfaceSeen = false;
        boolean peerSeen = false;
        final Set<String> seenInterface = new HashSet<>();
        final Set<String> seenPeer = new HashSet<>();
        int keptKeys = 0;
        for (String raw : canonical.split("\\r?\\n", -1)) {
            String line = raw.trim();
            if (line.isEmpty()) continue;
            if (line.equals("[Interface]")) {
                if (interfaceSeen || peerSeen) {
                    throw new IllegalArgumentException("Duplicated WG interface section.");
                }
                interfaceSeen = true;
                section = "Interface";
                output.append("[Interface]\n");
                continue;
            }
            if (line.equals("[Peer]")) {
                if (!interfaceSeen || peerSeen) {
                    throw new IllegalArgumentException("Not exactly one WG peer.");
                }
                peerSeen = true;
                section = "Peer";
                output.append("\n[Peer]\n");
                continue;
            }
            int equal = line.indexOf('=');
            if (equal < 1 || equal >= line.length() - 1
                    || (!section.equals("Interface") && !section.equals("Peer"))) {
                throw new IllegalArgumentException("Unrecognized canonical WG line.");
            }
            String key = line.substring(0, equal).trim();
            String value = line.substring(equal + 1).trim();
            if (value.isEmpty() || value.length() > 2048
                    || value.indexOf('\u0000') >= 0
                    || value.indexOf('\r') >= 0
                    || value.indexOf('\n') >= 0) {
                throw new IllegalArgumentException("Invalid canonical WG value.");
            }
            if (section.equals("Interface")) {
                if (key.equals("Address") || key.equals("DNS")
                        || key.equals("MTU") || key.equals("Table")
                        || key.equals("IncludedApplications")
                        || key.equals("ExcludedApplications")) {
                    // Deliberately excluded: the journaled link-only lab
                    // applies addresses separately and never changes DNS.
                    continue;
                }
                if (!key.equals("PrivateKey") && !key.equals("ListenPort")) {
                    throw new IllegalArgumentException("Unknown interface option.");
                }
                if (!seenInterface.add(key)) {
                    throw new IllegalArgumentException("Duplicate interface key.");
                }
            } else {
                if (!key.equals("PublicKey") && !key.equals("PresharedKey")
                        && !key.equals("AllowedIPs")
                        && !key.equals("Endpoint")
                        && !key.equals("PersistentKeepalive")) {
                    throw new IllegalArgumentException("Unknown peer option.");
                }
                if (!seenPeer.add(key)) {
                    throw new IllegalArgumentException("Duplicate peer key.");
                }
            }
            keptKeys++;
            output.append(key).append(" = ").append(value).append('\n');
        }
        if (!interfaceSeen || !peerSeen
                || !seenInterface.contains("PrivateKey")
                || !seenPeer.contains("PublicKey")
                || !seenPeer.contains("AllowedIPs")
                || keptKeys < 3) {
            throw new IllegalArgumentException("Missing required WG setconf fields.");
        }
        return output.toString();
    }
}
