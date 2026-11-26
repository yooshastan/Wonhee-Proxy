package com.yooshastan.wonheeproxy;

/** Read-only regression of the Pixel 8a Android 16 netfilter tool output. */
public final class RootNetfilterHelpCapabilitiesTest {
    private static void check(boolean success, String reason) {
        if (!success) throw new AssertionError(reason);
    }

    private static final String OWNER =
            "    --ipv6      -6              Error (line is ignored by iptables-restore)\n"
            + "[!] --uid-owner userid[-userid]      Match local UID\n";
    private static final String TCP = "--dport ...\n";
    private static final String UDP = " --dport ...\n";
    private static final String MARK =
            " --set-xmark value[/mask]  Clear bits in mask and XOR value into nfmark\n"
            + " --set-mark value[/mask]   Clear bits in mask and OR value into nfmark\n";

    private static RootNetfilterHelpCapabilities.Report report(String v4,
            String v4Owner, String v4Tcp, String v4Udp, String v4Mark,
            String v6, String v6Owner, String v6Tcp, String v6Udp, String v6Mark) {
        return RootNetfilterHelpCapabilities.review(v4, v4Owner, v4Tcp, v4Udp,
                v4Mark, v6, v6Owner, v6Tcp, v6Udp, v6Mark);
    }

    public static void main(String[] args) {
        String v4 = "iptables v1.8.11 (legacy)";
        String v6 = "ip6tables v1.8.11 (legacy)";
        RootNetfilterHelpCapabilities.Report captured =
                report(v4, OWNER, TCP, UDP, MARK, v6,
                        OWNER.replace("--ipv6", "--ipv4"), TCP, UDP, MARK);
        check(captured.bothFamiliesAdvertiseSyntax(),
                "Both Android legacy utilities advertise UID, TCP/UDP and MARK.");
        check(!captured.activationAllowed(),
                "Advertised CLI help cannot authorize kernel networking changes.");
        check(captured.summary().contains("Activation disabled."),
                "UI must not claim working packet routing.");

        RootNetfilterHelpCapabilities.Report missingV6 =
                report(v4, OWNER, TCP, UDP, MARK, v6, OWNER, TCP, UDP, "");
        check(!missingV6.bothFamiliesAdvertiseSyntax(),
                "A missing IPv6 MARK extension cannot silently fall back.");

        RootNetfilterHelpCapabilities.Report nft =
                report("iptables v1.8.11 (nf_tables)", OWNER, TCP, UDP, MARK,
                        "ip6tables v1.8.11 (nf_tables)", OWNER, TCP, UDP, MARK);
        check(!nft.bothFamiliesAdvertiseSyntax(),
                "Backend switch requires a separate capability audit.");

        RootNetfilterHelpCapabilities.Report bogus =
                report(v4, OWNER.replace("--uid-owner", "--uid-owner-fake"),
                        TCP, UDP, MARK, v6, OWNER, TCP, UDP, MARK);
        check(!bogus.bothFamiliesAdvertiseSyntax(),
                "Prefix matches must not impersonate UID owner selectors.");

        RootNetfilterHelpCapabilities.Report noMark =
                report(v4, OWNER, TCP, UDP, "--set-mark value[/mask]",
                        v6, OWNER, TCP, UDP, MARK);
        check(!noMark.bothFamiliesAdvertiseSyntax(),
                "Both MARK targets must be advertised to pass this conservative gate.");
        System.out.println("RootNetfilterHelpCapabilitiesTest passed");
    }
}
