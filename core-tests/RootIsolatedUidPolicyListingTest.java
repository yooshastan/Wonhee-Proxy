package com.yooshastan.wonheeproxy;

/** Rootless readback regressions based on Android ip rule / route formatting. */
public final class RootIsolatedUidPolicyListingTest {
    private static void check(RootIsolatedUidPolicyListing.Match expected,
            RootIsolatedUidPolicyListing.Match actual, String reason) {
        if (expected != actual) {
            throw new AssertionError(reason + ": " + actual);
        }
    }

    public static void main(String[] args) {
        RootIsolatedUidPolicyListing.Match yes =
                RootIsolatedUidPolicyListing.Match.EXACT;
        RootIsolatedUidPolicyListing.Match no =
                RootIsolatedUidPolicyListing.Match.ABSENT;
        RootIsolatedUidPolicyListing.Match foreign =
                RootIsolatedUidPolicyListing.Match.FOREIGN_OR_CHANGED;
        String rule = "12800: from all fwmark 0x0/0x20000 iif lo "
                + "uidrange 10341-10341 lookup 51000\n";
        check(yes, RootIsolatedUidPolicyListing.selector(
                rule, 4, 12800, 10341, 51000), "Exact IPv4 UID selector");
        check(yes, RootIsolatedUidPolicyListing.selector(
                rule, 6, 12800, 10341, 51000), "Exact IPv6 UID selector");
        check(no, RootIsolatedUidPolicyListing.selector(
                "10000: from all lookup legacy_system\n", 4, 12800,
                10341, 51000), "Missing owned priority");
        check(foreign, RootIsolatedUidPolicyListing.selector(
                rule.replace("51000", "51001"), 4, 12800, 10341, 51000),
                "Different routing table");
        check(foreign, RootIsolatedUidPolicyListing.selector(
                rule.replace("0x0/0x20000", "0x0/0x1ffff"),
                4, 12800, 10341, 51000), "Changed Android fwmark selection");
        check(foreign, RootIsolatedUidPolicyListing.selector(
                rule.replace("10341-10341", "10341-10342"),
                4, 12800, 10341, 51000), "Widened UID range");
        check(foreign, RootIsolatedUidPolicyListing.selector(
                rule + rule, 4, 12800, 10341, 51000),
                "Duplicate reserved selector priority");
        check(foreign, RootIsolatedUidPolicyListing.selector(
                rule, 4, 12800, 999, 51000),
                "Non-app UID must not be treated as owned");

        check(yes, RootIsolatedUidPolicyListing.terminalDefault(
                "default dev wnm68fe81200daa scope link\n"
                + "unreachable default metric 42700\n", 4),
                "Terminal unreachable route below tunnel default");
        check(yes, RootIsolatedUidPolicyListing.terminalDefault(
                "unreachable default proto boot metric 42700\n", 6),
                "Common kernel proto boot display");
        check(no, RootIsolatedUidPolicyListing.terminalDefault(
                "default dev wnm68fe81200daa\n", 4),
                "Missing failsafe block");
        check(foreign, RootIsolatedUidPolicyListing.terminalDefault(
                "unreachable default metric 400\n", 4),
                "Foreign metric can change route selection");
        check(foreign, RootIsolatedUidPolicyListing.terminalDefault(
                "unreachable default metric 42700\n"
                + "unreachable default metric 42700\n", 4),
                "Duplicate terminal block");
        check(foreign, RootIsolatedUidPolicyListing.terminalDefault(
                "unreachable default via 192.0.2.1 metric 42700\n", 4),
                "Additional unexpected attributes");

        System.out.println("RootIsolatedUidPolicyListingTest passed");
    }
}
