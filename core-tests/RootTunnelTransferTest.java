package com.yooshastan.wonheeproxy;

import java.util.Arrays;
import java.util.Collections;

public final class RootTunnelTransferTest {
    private static void check(boolean ok) { if (!ok) throw new AssertionError(); }

    public static void main(String[] ignored) {
        RootTunnelTransfer before = RootTunnelTransfer.parse(Arrays.asList("peerKey 800 1200"));
        RootTunnelTransfer after = RootTunnelTransfer.parse(Arrays.asList("peerKey\t925\t1400"));
        check(before != null && before.received == 800 && before.sent == 1200);
        check("rx +125 B; tx +200 B".equals(RootTunnelTransfer.delta(before, after)));
        check(RootTunnelTransfer.parse(Arrays.asList("peerKey 1 -1")) == null);
        check(RootTunnelTransfer.parse(Arrays.asList("peerKey 1 2", "second 1 2")) == null);
        check(RootTunnelTransfer.parse(Arrays.asList("peerKey 18446744073709551615 2")) == null);
        check(RootTunnelTransfer.parse(Collections.emptyList()) == null);
        check("UNAVAILABLE / COUNTER RESET".equals(RootTunnelTransfer.delta(after, before)));
        System.out.println("RootTunnelTransferTest passed");
    }
}
