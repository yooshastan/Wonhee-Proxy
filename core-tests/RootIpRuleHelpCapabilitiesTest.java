package com.yooshastan.wonheeproxy;

/**
 * Tests the actual 2026-11-19 Pixel 8a Android 16 help text. Read-only;
 * never installs routes or touches the kernel.
 */
public final class RootIpRuleHelpCapabilitiesTest {
    private static void check(boolean ok, String label) {
        if (!ok) throw new AssertionError(label);
    }

    private static final String PIXEL_8A_HELP =
            "Usage: ip rule { add | del } SELECTOR ACTION\n"
            + "       ip rule { flush | save | restore }\n"
            + "       ip rule [ list [ SELECTOR ]]\n"
            + "SELECTOR := [ not ] [ from PREFIX ] [ to PREFIX ] [ tos TOS ] "
            + "[ fwmark FWMARK[/MASK] ]\n"
            + "            [ iif STRING ] [ oif STRING ] [ pref NUMBER ] [ l3mdev ]\n"
            + "            [ uidrange NUMBER-NUMBER ]\n"
            + "ACTION := [ table TABLE_ID ]\n"
            + "          [ nat ADDRESS ]\n"
            + "          [ realms [SRCREALM/]DSTREALM ]\n"
            + "          [ goto NUMBER ]\n"
            + "          SUPPRESSOR\n";

    public static void main(String[] args) {
        RootIpRuleHelpCapabilities.Report observed =
                RootIpRuleHelpCapabilities.review(PIXEL_8A_HELP, PIXEL_8A_HELP);
        check(observed.helpReadable, "Reported Android help must be parsed.");
        check(observed.uidAndMarkAdvertised,
                "Observed Android ip command exposes UID and fwmark selectors.");
        check(!observed.directL4Advertised,
                "Observed Android ip command does NOT advertise ipproto/dport.");
        check(!observed.unreachableActionAdvertised,
                "Do not infer command-line unreachable from an existing RPDB rule.");
        check(!observed.activationAllowed()
                        && observed.summary().contains("NOT ADVERTISED"),
                "Help check is not authorization for live multi-exit routing.");

        String modern = PIXEL_8A_HELP
                .replace("[ uidrange NUMBER-NUMBER ]",
                        "[ uidrange NUMBER-NUMBER ] [ ipproto PROTOCOL ] "
                        + "[ dport NUMBER ]")
                .replace("[ table TABLE_ID ]",
                        "[ table TABLE_ID ] [ unreachable ]");
        RootIpRuleHelpCapabilities.Report upgraded =
                RootIpRuleHelpCapabilities.review(modern, modern);
        check(upgraded.directL4Advertised && upgraded.unreachableActionAdvertised,
                "Advertised modern CLI syntax should be recognized.");
        check(!upgraded.activationAllowed(),
                "An advanced userspace ip binary still needs kernel/live safety tests.");
        RootIpRuleHelpCapabilities.Report asym =
                RootIpRuleHelpCapabilities.review(modern, PIXEL_8A_HELP);
        check(asym.helpReadable && !asym.directL4Advertised
                        && !asym.unreachableActionAdvertised,
                "IPv4 support cannot conceal missing IPv6 CLI selectors.");

        RootIpRuleHelpCapabilities.Report unknown =
                RootIpRuleHelpCapabilities.review("permission denied", modern);
        check(!unknown.helpReadable && !unknown.uidAndMarkAdvertised
                        && !unknown.activationAllowed(),
                "Unreadable help must fail safely.");
        String misleading = PIXEL_8A_HELP.replace("uidrange", "uidrange_extra");
        check(!RootIpRuleHelpCapabilities.review(misleading, modern)
                        .uidAndMarkAdvertised,
                "Selector names must match complete tokens, not prefixes.");
        System.out.println("RootIpRuleHelpCapabilitiesTest passed");
    }
}
