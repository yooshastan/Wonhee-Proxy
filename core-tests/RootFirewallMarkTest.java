package com.yooshastan.wonheeproxy;

import java.util.Arrays;
import java.util.Collections;

public final class RootFirewallMarkTest {
    private static void check(boolean value) {
        if (!value) throw new AssertionError();
    }

    public static void main(String[] ignored) {
        check(RootFirewallMark.parse(Arrays.asList("0xc91c0")) == 0xc91c0L);
        check(RootFirewallMark.parse(Arrays.asList("51820")) == 51820L);
        check(RootFirewallMark.parse(Arrays.asList("0xffffffff")) == 0xffffffffL);
        check(RootFirewallMark.parse(Arrays.asList("off")) == 0);
        check(RootFirewallMark.parse(Arrays.asList("0")) == 0);
        check(RootFirewallMark.parse(Arrays.asList("0x0")) == 0);
        check(RootFirewallMark.parse(Arrays.asList("0x100000000")) == 0);
        check(RootFirewallMark.parse(Arrays.asList("0xc91c0", "extra")) == 0);
        check(RootFirewallMark.parse(Arrays.asList("$(whoami)")) == 0);
        check(RootFirewallMark.parse(Collections.emptyList()) == 0);
        check(RootFirewallMark.distinctNonzero(0xc91c0, 0xc6488));
        check(!RootFirewallMark.distinctNonzero(0, 0xc6488));
        check(!RootFirewallMark.distinctNonzero(0xc91c0, 0xc91c0));
        check(RootFirewallMark.sharedAndroidProtectBit(0x20000, 0x20000));
        check(!RootFirewallMark.sharedAndroidProtectBit(0xc91c0, 0xc91c0));
        check(!RootFirewallMark.sharedAndroidProtectBit(0x20000, 0xc6488));
        check("0x20000".equals(RootFirewallMark.display(0x20000)));
        check("OFF/UNVERIFIED".equals(RootFirewallMark.display(0)));
        System.out.println("RootFirewallMarkTest passed");
    }
}
