package com.yooshastan.wonheeproxy;

import java.util.List;

/**
 * Sensitive-data-free audit of two already-selected, separately owned
 * WireGuard peers. Inputs are the output of read-only 'wg show ...' calls.
 *
 * This is NOT reachability proof: a recent handshake only demonstrates
 * authenticated peer contact, not correct DNS, physical underlay, UID
 * routing or fail-closed behavior. Never log endpoint IPs or public keys.
 */
final class RootIsolatedTwoPeerHandshakeAudit {
    static final class Peer {
        final String label;
        final boolean identityMatches;
        final boolean recentHandshake;
        final long handshakeAgeSeconds;
        final long bytesReceived;
        final long bytesSent;

        Peer(String label, boolean identityMatches, boolean recentHandshake,
                long handshakeAgeSeconds, long bytesReceived, long bytesSent) {
            this.label = label;
            this.identityMatches = identityMatches;
            this.recentHandshake = recentHandshake;
            this.handshakeAgeSeconds = handshakeAgeSeconds;
            this.bytesReceived = bytesReceived;
            this.bytesSent = bytesSent;
        }

        String publicSummary() {
            return label + ": peer identity " + (identityMatches ? "verified" : "NOT VERIFIED")
                    + ", handshake " + (recentHandshake
                    ? ("recent (" + handshakeAgeSeconds + "s ago)") : "not recent/unknown")
                    + ", rx=" + bytesReceived + ", tx=" + bytesSent
                    + ". No application routing or DNS safety claim.";
        }
    }

    private RootIsolatedTwoPeerHandshakeAudit() { }

    static Peer inspect(String label, String expectedPeerKey,
            List<String> handshake, List<String> transfer,
            long currentEpochSeconds, long maxAgeSeconds) {
        if (label == null || !label.matches("[A-Za-z0-9 _-]{1,40}")
                || expectedPeerKey == null
                || !expectedPeerKey.matches("[A-Za-z0-9+/]{43}=")
                || currentEpochSeconds <= 0 || maxAgeSeconds <= 0
                || maxAgeSeconds > 3600) {
            throw new IllegalArgumentException("Invalid peer audit parameters.");
        }
        if (handshake == null || transfer == null
                || handshake.size() != 1 || transfer.size() != 1) {
            return new Peer(label, false, false, -1, -1, -1);
        }
        String[] h = handshake.get(0).trim().split("\\s+");
        String[] t = transfer.get(0).trim().split("\\s+");
        if (h.length != 2 || t.length != 3
                || !expectedPeerKey.equals(h[0])
                || !expectedPeerKey.equals(t[0])) {
            return new Peer(label, false, false, -1, -1, -1);
        }
        try {
            long epoch = Long.parseLong(h[1]);
            long rx = Long.parseLong(t[1]);
            long tx = Long.parseLong(t[2]);
            if (epoch < 0 || rx < 0 || tx < 0 || epoch > currentEpochSeconds) {
                return new Peer(label, false, false, -1, -1, -1);
            }
            boolean ever = epoch != 0;
            long age = ever ? currentEpochSeconds - epoch : -1;
            return new Peer(label, true, ever && age <= maxAgeSeconds,
                    age, rx, tx);
        } catch (NumberFormatException invalid) {
            return new Peer(label, false, false, -1, -1, -1);
        }
    }

    static boolean twoRecentDistinct(Peer left, Peer right) {
        return left != null && right != null
                && !left.label.equals(right.label)
                && left.identityMatches && right.identityMatches
                && left.recentHandshake && right.recentHandshake;
    }
}
