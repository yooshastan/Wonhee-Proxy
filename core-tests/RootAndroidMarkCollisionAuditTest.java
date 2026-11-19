package com.yooshastan.wonheeproxy;

/**
 * Read-only regression from Pixel 8a Android 16 mangle/OUTPUT and RPDB
 * snapshots on 2026-11-19. No shell calls, no packet mutations.
 */
public final class RootAndroidMarkCollisionAuditTest {
    private static void check(boolean pass, String reason) {
        if (!pass) throw new AssertionError(reason);
    }

    private static final String MANGLE =
            "-N connmark_mangle_OUTPUT\n"
            + "-A OUTPUT -j connmark_mangle_OUTPUT\n"
            + "-A connmark_mangle_OUTPUT -m connmark --mark 0x0/0xfffff "
            + "-j CONNMARK --save-mark --nfmask 0xfffff --ctmask 0xfffff\n"
            + "-A bw_mangle_POSTROUTING -j MARK --set-xmark 0x0/0x100000\n"
            + "-A routectrl_mangle_INPUT -i wlan0 -j MARK "
            + "--set-xmark 0x30073/0x7fefffff\n"
            + "-A wakeupctrl_mangle_INPUT -i wlan0 "
            + "-m mark --mark 0x80000000/0x80000000 "
            + "-j NFLOG --nflog-group 3\n";
    private static final String RULES =
            "10000: from all fwmark 0xc0000/0xd0000 lookup legacy_system\n"
            + "15998: from all fwmark 0x10073/0x1ffff "
            + "iif lo uidrange 0-2147483647 lookup wlan0\n"
            + "31000: from all fwmark 0xc0000/0xcffff iif lo lookup wlan0\n";

    public static void main(String[] args) {
        RootAndroidMarkCollisionAudit.Report observed =
                RootAndroidMarkCollisionAudit.review(MANGLE, RULES, MANGLE, RULES);
        check(observed.noUnreferencedBitsObserved(),
                "Observed v4/v6 masks collectively reference all 32 mark bits.");
        check(observed.ipv4.writeBits == 0x7fffffffL,
                "Broad Android set-xmark operations cover bits 0..30.");
        check((observed.ipv4.connmarkBits & 0xfffffL) == 0xfffffL,
                "First-packet CONNMARK save touches the low 20 bits.");
        check((observed.ipv4.referencedBits & 0x80000000L) != 0,
                "Android wakeup logging refers to mark bit 31.");
        check(observed.ipv4.observedBits() == 0xffffffffL,
                "Observed Android bit coverage leaves no provably unused bit.");
        check(!observed.activationAllowed()
                && !observed.candidateVerifiedFree(0x100000L)
                && !observed.candidateVerifiedFree(0x20000000L)
                && !observed.candidateVerifiedFree(0x80000000L),
                "Never auto-allocate bits from observed netd traffic masks.");
        check(observed.summary().contains("all 32 bits"),
                "Readiness must explain overbroad mark-masking footprint.");

        RootAndroidMarkCollisionAudit.Report missingHigh =
                RootAndroidMarkCollisionAudit.review(
                        MANGLE.replace("-m mark --mark 0x80000000/0x80000000",
                                "-m limit --limit 10/sec"),
                        RULES, MANGLE, RULES);
        check(!missingHigh.noUnreferencedBitsObserved(),
                "Do not infer all bits referenced if a high-bit rule disappears.");
        check(!missingHigh.candidateVerifiedFree(0x80000000L),
                "A missing historical high-bit reference never grants ownership.");

        RootAndroidMarkCollisionAudit.Report unreadable =
                RootAndroidMarkCollisionAudit.review("Permission denied",
                        RULES, MANGLE, RULES);
        check(!unreadable.ipv4.readable && !unreadable.activationAllowed(),
                "Missing shell visibility fails closed.");

        RootAndroidMarkCollisionAudit.Report malformed =
                RootAndroidMarkCollisionAudit.review(
                        MANGLE + "-A OUTPUT -j MARK --set-xmark invalid\n",
                        RULES, MANGLE, RULES);
        check(!malformed.ipv4.readable && !malformed.activationAllowed(),
                "Unknown kernel mark write syntax cannot certify any bit.");

        System.out.println("RootAndroidMarkCollisionAuditTest passed");
    }
}
