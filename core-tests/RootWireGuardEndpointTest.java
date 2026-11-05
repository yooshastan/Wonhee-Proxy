package com.yooshastan.wonheeproxy;

import java.util.Arrays;

public final class RootWireGuardEndpointTest {
    private static void expect(String entry, boolean expected) {
        boolean result = RootWireGuardEndpoint.hasSingleNumericEndpoint(Arrays.asList(entry));
        if (result != expected) throw new AssertionError(entry);
    }

    public static void main(String[] ignored) {
        expect("publickey\t192.0.2.10:51820", true);
        expect("publickey\t[2001:db8::1]:51820", true);
        expect("publickey\t(none)", false);
        expect("publickey\tvpn.example.com:51820", false);
        expect("publickey\t999.0.2.10:51820", false);
        expect("publickey\t192.0.2.10:65536", false);
        expect("publickey\t192.0.2.10:0", false);
        expect("publickey\t[2001:db8::1]", false);
        if (RootWireGuardEndpoint.hasSingleNumericEndpoint(Arrays.asList(
                "peer1\t192.0.2.10:51820", "peer2\t192.0.2.11:51820"))) {
            throw new AssertionError("Multiple peers must not pass");
        }
        System.out.println("RootWireGuardEndpointTest passed");
    }
}
