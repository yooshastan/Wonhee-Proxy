package com.yooshastan.wonheeproxy;

import java.util.Arrays;
import java.util.Collections;

public final class RootIsolatedTwoPeerHandshakeAuditTest {
    private static final String EU_KEY =
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    private static final String US_KEY =
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";

    private static void check(boolean pass, String why) {
        if (!pass) throw new AssertionError(why);
    }

    private static RootIsolatedTwoPeerHandshakeAudit.Peer peer(
            String label, String pub, long epoch) {
        return RootIsolatedTwoPeerHandshakeAudit.inspect(
                label, pub,
                Collections.singletonList(pub + "\t" + epoch),
                Collections.singletonList(pub + "\t17000\t18000"),
                2000, 120);
    }

    public static void main(String[] args) {
        RootIsolatedTwoPeerHandshakeAudit.Peer eu = peer("Europe", EU_KEY, 1950);
        RootIsolatedTwoPeerHandshakeAudit.Peer us = peer("America", US_KEY, 1960);
        check(RootIsolatedTwoPeerHandshakeAudit.twoRecentDistinct(eu, us),
                "Two independent authenticated peers with recent handshakes");
        check(eu.handshakeAgeSeconds == 50 && eu.bytesReceived == 17000,
                "Handshake age and transfer counters preserved");
        check(!eu.publicSummary().contains(EU_KEY)
                        && !us.publicSummary().contains(US_KEY)
                        && !eu.publicSummary().contains("endpoint")
                        && !eu.publicSummary().contains("DNS safety")
                        && eu.publicSummary().contains("handshake 50s ago")
                        && eu.publicSummary().contains("rx=17000"),
                "Concise readout has verified state/counters but no secrets or repeated disclaimer");

        check(!RootIsolatedTwoPeerHandshakeAudit.twoRecentDistinct(
                        eu, peer("America", US_KEY, 1000)),
                "Old handshake not sufficient");
        check(!RootIsolatedTwoPeerHandshakeAudit.twoRecentDistinct(
                        eu, peer("America", US_KEY, 0)),
                "Never-handshaken peer not sufficient");
        check(!RootIsolatedTwoPeerHandshakeAudit.twoRecentDistinct(
                        eu, peer("Europe", US_KEY, 1970)),
                "A duplicate label is not two independent peers");
        check(!RootIsolatedTwoPeerHandshakeAudit.twoRecentDistinct(
                        eu, peer("America", US_KEY, 2010)),
                "Future handshake timestamp is invalid");

        RootIsolatedTwoPeerHandshakeAudit.Peer mismatch =
                RootIsolatedTwoPeerHandshakeAudit.inspect(
                        "America", US_KEY,
                        Collections.singletonList(EU_KEY + " 1900"),
                        Collections.singletonList(US_KEY + " 50 80"), 2000, 120);
        check(!mismatch.identityMatches && !mismatch.recentHandshake,
                "Never adopt another peer's traffic counters");
        RootIsolatedTwoPeerHandshakeAudit.Peer broken =
                RootIsolatedTwoPeerHandshakeAudit.inspect(
                        "America", US_KEY,
                        Arrays.asList(US_KEY + " 1900", US_KEY + " 1901"),
                        Collections.singletonList(US_KEY + " 50 80"), 2000, 120);
        check(!broken.identityMatches,
                "Duplicate peers in kernel readback must refuse");
        RootIsolatedTwoPeerHandshakeAudit.Peer negative =
                RootIsolatedTwoPeerHandshakeAudit.inspect(
                        "America", US_KEY,
                        Collections.singletonList(US_KEY + " 1998"),
                        Collections.singletonList(US_KEY + " -1 12"), 2000, 120);
        check(!negative.identityMatches,
                "Negative or invalid counters invalidate kernel evidence");

        System.out.println("RootIsolatedTwoPeerHandshakeAuditTest passed");
    }
}
