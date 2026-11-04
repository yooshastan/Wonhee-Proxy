package com.yooshastan.wonheeproxy;

import java.util.Arrays;
import java.util.Collections;

public final class MultiTunnelPacketRouterTest {
    private static byte[] ipv4(int a, int b, int c, int d) {
        byte[] packet = new byte[20];
        packet[0] = 0x45;
        packet[2] = 0;
        packet[3] = 20;
        packet[12] = 10;
        packet[13] = 111;
        packet[14] = 22;
        packet[15] = 33;
        packet[16] = (byte) a;
        packet[17] = (byte) b;
        packet[18] = (byte) c;
        packet[19] = (byte) d;
        return packet;
    }

    private static byte[] ipv6() {
        byte[] packet = new byte[40];
        packet[0] = 0x60;
        packet[24] = 0x20;
        packet[25] = 0x01;
        packet[26] = 0x48;
        packet[27] = (byte) 0x60;
        packet[39] = 1;
        return packet;
    }

    private static void equals(MultiTunnelPacketRouter.Target expected,
                               MultiTunnelPacketRouter.Target actual) {
        if (expected != actual) {
            throw new AssertionError("Expected " + expected + " got " + actual);
        }
    }

    private static void reject(String cidr) {
        try {
            MultiTunnelPacketRouter.forFullTunnel(
                    Collections.singletonList(cidr), true, true);
            throw new AssertionError("Unsafe home CIDR accepted.");
        } catch (IllegalArgumentException expected) { }
    }

    public static void main(String[] args) {
        MultiTunnelPacketRouter router = MultiTunnelPacketRouter.forFullTunnel(
                Arrays.asList("10.77.0.0/24", "192.168.50.0/24"), true, true);

        equals(MultiTunnelPacketRouter.Target.HOME,
                router.route(ipv4(10, 77, 0, 1), true, true));
        equals(MultiTunnelPacketRouter.Target.HOME,
                router.route(ipv4(192, 168, 50, 10), true, true));
        equals(MultiTunnelPacketRouter.Target.INTERNET,
                router.route(ipv4(8, 8, 8, 8), true, true));
        equals(MultiTunnelPacketRouter.Target.INTERNET,
                router.route(ipv4(192, 168, 1, 1), true, true));
        // Never reroute unavailable private destinations through AirVPN.
        equals(MultiTunnelPacketRouter.Target.DROP,
                router.route(ipv4(10, 77, 0, 1), false, true));
        // Never reroute unavailable Internet traffic directly to the ISP.
        equals(MultiTunnelPacketRouter.Target.DROP,
                router.route(ipv4(8, 8, 8, 8), true, false));
        equals(MultiTunnelPacketRouter.Target.INTERNET,
                router.route(ipv6(), true, true));
        equals(MultiTunnelPacketRouter.Target.DROP,
                router.route(ipv6(), true, false));
        MultiTunnelPacketRouter noIpv6 = MultiTunnelPacketRouter.forFullTunnel(
                Collections.singletonList("10.77.0.0/24"), true, false);
        equals(MultiTunnelPacketRouter.Target.DROP,
                noIpv6.route(ipv6(), true, true));

        equals(MultiTunnelPacketRouter.Target.DROP,
                router.route(new byte[] { 0x45 }, true, true));
        equals(MultiTunnelPacketRouter.Target.DROP,
                router.route(new byte[] { 0 }, true, true));
        equals(MultiTunnelPacketRouter.Target.DROP,
                router.route(null, true, true));
        byte[] malformed = ipv4(10, 77, 0, 1);
        malformed[0] = 0x44; // IHL < 20 bytes.
        equals(MultiTunnelPacketRouter.Target.DROP,
                router.route(malformed, true, true));
        malformed = ipv4(8, 8, 8, 8);
        malformed[3] = 40; // Declared length > packet size.
        equals(MultiTunnelPacketRouter.Target.DROP,
                router.route(malformed, true, true));
        malformed = ipv6();
        malformed[5] = 10; // Truncated IPv6 payload.
        equals(MultiTunnelPacketRouter.Target.DROP,
                router.route(malformed, true, true));

        reject("0.0.0.0/0");
        reject("8.8.8.0/24");
        reject("10.0.0.0/7");
        reject("10.77.0.0/0");
        reject("192.168.1.1/abc");
        reject("10.077.0.0/24");
        reject("100.64.0.0/10");
        reject("::/0");
        try {
            MultiTunnelPacketRouter.forFullTunnel(
                    Arrays.asList("10.77.0.0/24", "10.77.0.128/25"), true, true);
            throw new AssertionError("Overlapping home routes accepted.");
        } catch (IllegalArgumentException expected) { }
        try {
            MultiTunnelPacketRouter.forFullTunnel(
                    Collections.singletonList("10.77.0.0/24"), false, true);
            throw new AssertionError("No IPv4 exit accepted.");
        } catch (IllegalArgumentException expected) { }
        try {
            MultiTunnelPacketRouter.forFullTunnel(
                    Collections.emptyList(), true, true);
            throw new AssertionError("No home routes accepted.");
        } catch (IllegalArgumentException expected) { }
        System.out.println("PASS MultiTunnelPacketRouterTest");
    }
}
