package com.yooshastan.wonheeproxy;

import java.util.Arrays;
import java.util.Collections;

public final class MultiTunnelPacketFlowTest {
    private static final String TUN = "10.255.0.1";
    private static final String HOME_CLIENT = "10.6.0.2";
    private static final String EXIT_CLIENT = "10.159.187.150";

    private static int u16(byte[] p, int i) {
        return ((p[i] & 255) << 8) | (p[i + 1] & 255);
    }

    private static void put16(byte[] p, int at, int v) {
        p[at] = (byte) (v >>> 8); p[at + 1] = (byte) v;
    }

    private static void putIp(byte[] p, int at, String ipv4) {
        int value = MultiTunnelIpv4Rewriter.parseIpv4(ipv4);
        p[at] = (byte) (value >>> 24); p[at + 1] = (byte) (value >>> 16);
        p[at + 2] = (byte) (value >>> 8); p[at + 3] = (byte) value;
    }

    private static String ip(byte[] p, int at) {
        return (p[at] & 255) + "." + (p[at + 1] & 255) + "."
                + (p[at + 2] & 255) + "." + (p[at + 3] & 255);
    }

    /** Independent test implementation of RFC1071 16-bit one's-complement. */
    private static int verifyChecksum(byte[] p, int off, int count, long seed) {
        for (int i = off; i < off + count; i += 2) {
            seed += (p[i] & 255) * 256L;
            if (i + 1 < off + count) seed += p[i + 1] & 255;
        }
        while (seed > 65535L) seed = (seed % 65536L) + (seed / 65536L);
        return (int) (65535L - seed);
    }

    private static long pseudo(byte[] p, int payloadLen) {
        return u16(p, 12) + u16(p, 14) + u16(p, 16) + u16(p, 18)
                + (p[9] & 255) + payloadLen;
    }

    private static byte[] packet(int protocol, String source, String destination) {
        int layer4 = protocol == 6 ? 24 : protocol == 17 ? 13 : 8;
        byte[] p = new byte[20 + layer4];
        p[0] = 0x45; p[1] = 0; put16(p, 2, p.length);
        p[8] = 64; p[9] = (byte) protocol;
        putIp(p, 12, source); putIp(p, 16, destination);
        if (protocol == 6) {
            put16(p, 20, 51324); put16(p, 22, 443);
            p[32] = 0x50; p[33] = 0x18; p[40] = 1; p[41] = 2;
            p[42] = 3; p[43] = 4;
            put16(p, 36, verifyChecksum(p, 20, layer4, pseudo(p, layer4)));
        } else if (protocol == 17) {
            put16(p, 20, 51324); put16(p, 22, 53); put16(p, 24, layer4);
            for (int i = 28; i < p.length; i++) p[i] = (byte) (i - 28 + 1);
            int checksum = verifyChecksum(p, 20, layer4, pseudo(p, layer4));
            put16(p, 26, checksum == 0 ? 0xffff : checksum);
        } else if (protocol == 1) {
            p[20] = 8; put16(p, 24, 1234); put16(p, 26, 3);
            put16(p, 22, verifyChecksum(p, 20, layer4, 0));
        }
        put16(p, 10, verifyChecksum(p, 0, 20, 0));
        return p;
    }

    private static void validChecksums(byte[] packet) {
        equal(0, verifyChecksum(packet, 0, 20, 0), "IPv4 header checksum");
        int proto = packet[9] & 255;
        if (proto == 6 || (proto == 17 && u16(packet, 26) != 0)) {
            equal(0, verifyChecksum(packet, 20, packet.length - 20,
                    pseudo(packet, packet.length - 20)), "transport checksum");
        } else if (proto == 1) {
            equal(0, verifyChecksum(packet, 20, packet.length - 20, 0), "ICMP checksum");
        }
    }

    private static void equal(Object want, Object have, String label) {
        if (!want.equals(have)) throw new AssertionError(label + ": want " + want + " got " + have);
    }

    private static void yes(boolean condition, String label) {
        if (!condition) throw new AssertionError(label);
    }

    private static void rejects(Runnable callable, String label) {
        try { callable.run(); throw new AssertionError("Accepted " + label); }
        catch (IllegalArgumentException expected) { }
    }

    public static void main(String[] args) {
        MultiTunnelPacketRouter router = MultiTunnelPacketRouter.forFullTunnel(
                Arrays.asList("10.6.0.0/24", "10.0.0.0/24"), true, true);
        MultiTunnelSessionLedger ledger = new MultiTunnelSessionLedger();
        MultiTunnelPacketFlow flow = new MultiTunnelPacketFlow(
                router, ledger, TUN, HOME_CLIENT, EXIT_CLIENT);
        byte[] lanRequest = packet(6, TUN, "10.0.0.169");
        yes(flow.outgoing(lanRequest).dropped(), "start closed");

        long h = ledger.begin(MultiTunnelPacketRouter.Target.HOME);
        long n = ledger.begin(MultiTunnelPacketRouter.Target.INTERNET);
        ledger.ready(MultiTunnelPacketRouter.Target.HOME, h);
        ledger.ready(MultiTunnelPacketRouter.Target.INTERNET, n);

        for (int protocol : new int[] { 6, 17, 1 }) {
            byte[] original = packet(protocol, TUN, "10.0.0.169");
            byte[] pristine = original.clone();
            MultiTunnelPacketFlow.Outbound toHome = flow.outgoing(original);
            equal(MultiTunnelPacketRouter.Target.HOME, toHome.target, "home dispatch");
            equal(HOME_CLIENT, ip(toHome.packet, 12), "home source rewrite");
            equal("10.0.0.169", ip(toHome.packet, 16), "home destination intact");
            validChecksums(toHome.packet);
            yes(Arrays.equals(original, pristine), "egress must not modify original");
            yes(flow.stillAuthorized(toHome), "fresh home permit");

            byte[] reply = packet(protocol, "10.0.0.169", HOME_CLIENT);
            byte[] received = flow.incoming(MultiTunnelPacketRouter.Target.HOME, reply);
            yes(received != null, "home ingress allowed");
            equal(TUN, ip(received, 16), "home reply restored to TUN");
            equal("10.0.0.169", ip(received, 12), "home reply source intact");
            validChecksums(received);
        }

        byte[] publicRequest = packet(17, TUN, "1.1.1.1");
        MultiTunnelPacketFlow.Outbound toExit = flow.outgoing(publicRequest);
        equal(MultiTunnelPacketRouter.Target.INTERNET, toExit.target, "exit dispatch");
        equal(EXIT_CLIENT, ip(toExit.packet, 12), "exit source rewrite");
        validChecksums(toExit.packet);
        byte[] response = flow.incoming(MultiTunnelPacketRouter.Target.INTERNET,
                packet(17, "1.1.1.1", EXIT_CLIENT));
        yes(response != null, "internet ingress allowed");
        equal(TUN, ip(response, 16), "exit reply restored to TUN");
        validChecksums(response);

        yes(flow.incoming(MultiTunnelPacketRouter.Target.INTERNET,
                packet(6, "10.0.0.169", EXIT_CLIENT)) == null,
                "AirVPN must not inject forged Home reply");
        yes(flow.incoming(MultiTunnelPacketRouter.Target.HOME,
                packet(6, "1.1.1.1", HOME_CLIENT)) == null,
                "Home must not inject public internet reply");
        yes(flow.incoming(MultiTunnelPacketRouter.Target.HOME,
                packet(6, "10.0.0.169", EXIT_CLIENT)) == null,
                "Home reply addressed to wrong session must drop");

        byte[] invalid = lanRequest.clone();
        invalid[10] ^= 1;
        yes(flow.outgoing(invalid).dropped(), "bad header checksum drops");
        invalid = lanRequest.clone(); invalid[6] = 0x20;
        yes(flow.outgoing(invalid).dropped(), "fragment drops");
        invalid = packet(17, TUN, "10.0.0.169"); invalid[25] = 9;
        yes(flow.outgoing(invalid).dropped(), "invalid UDP length drops");
        invalid = packet(1, TUN, "10.0.0.169"); invalid[20] = 3;
        yes(flow.outgoing(invalid).dropped(), "ICMP error with embedded IP drops");
        invalid = packet(6, TUN, "10.0.0.169"); invalid[32] = 0x10;
        yes(flow.outgoing(invalid).dropped(), "bad TCP offset drops");
        invalid = packet(6, "10.255.0.2", "10.0.0.169");
        yes(flow.outgoing(invalid).dropped(), "unexpected TUN source drops");
        byte[] ipv6 = new byte[40]; ipv6[0] = 0x60;
        yes(flow.outgoing(ipv6).dropped(), "IPv6 unavailable until correct mapping");

        byte[] noUdpChecksum = packet(17, TUN, "1.1.1.1");
        put16(noUdpChecksum, 26, 0);
        MultiTunnelPacketFlow.Outbound zeroUdp = flow.outgoing(noUdpChecksum);
        yes(!zeroUdp.dropped(), "IPv4 UDP zero-checksum remains valid");
        equal(0, u16(zeroUdp.packet, 26), "IPv4 UDP disabled checksum preserved");

        ledger.stop(MultiTunnelPacketRouter.Target.HOME);
        yes(flow.stillAuthorized(flow.outgoing(publicRequest)),
                "Internet permit survives Home stop");
        yes(flow.outgoing(lanRequest).dropped(), "no Home-to-AirVPN fallback");
        yes(!flow.stillAuthorized(flow.outgoing(lanRequest)), "drop is never authorized");
        ledger.stop(MultiTunnelPacketRouter.Target.INTERNET);
        yes(!flow.stillAuthorized(toExit), "old queued exit packet invalidated");
        yes(flow.outgoing(publicRequest).dropped(), "no direct ISP fallback");
        ledger.begin(MultiTunnelPacketRouter.Target.INTERNET);
        yes(!flow.stillAuthorized(toExit), "restart cannot revive old queued packet");

        rejects(() -> new MultiTunnelPacketFlow(router, ledger,
                TUN, HOME_CLIENT, HOME_CLIENT), "duplicate session addresses");
        rejects(() -> new MultiTunnelIpv4Rewriter("127.0.0.1", HOME_CLIENT), "loopback TUN");
        rejects(() -> new MultiTunnelIpv4Rewriter(TUN, "0.0.0.0"), "unspecified peer");
        rejects(() -> new MultiTunnelIpv4Rewriter(TUN, "10.06.0.2"), "ambiguous IPv4");
        System.out.println("PASS MultiTunnelPacketFlowTest");
    }
}
