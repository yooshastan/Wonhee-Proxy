package com.yooshastan.wonheeproxy;

import java.util.Arrays;

public final class RootlessTunTestPacketRouterTest {
    public static void main(String[] args) {
        expect(RootlessTunTestPacketRouter.Target.HOME, udp("198.18.1.10"));
        expect(RootlessTunTestPacketRouter.Target.INTERNET, udp("198.18.2.10"));
        expect(RootlessTunTestPacketRouter.Target.INTERNET, udp("198.19.4.20"));
        expect(RootlessTunTestPacketRouter.Target.DROP, udp("192.0.2.10"));
        expect(RootlessTunTestPacketRouter.Target.DROP, tcp("198.18.2.10"));

        byte[] fragmented = udp("198.18.1.10");
        fragmented[6] = 0x20;
        checksum(fragmented);
        expect(RootlessTunTestPacketRouter.Target.DROP, fragmented);

        byte[] badChecksum = udp("198.18.1.10");
        badChecksum[10] ^= 0x01;
        expect(RootlessTunTestPacketRouter.Target.DROP, badChecksum);

        byte[] badLength = udp("198.18.1.10");
        badLength[25] = 7;
        checksum(badLength);
        expect(RootlessTunTestPacketRouter.Target.DROP, badLength);

        expect(RootlessTunTestPacketRouter.Target.DROP, new byte[27]);
        expect(RootlessTunTestPacketRouter.Target.DROP, new byte[1281]);
        byte[] ipv6 = new byte[48];
        ipv6[0] = 0x60;
        expect(RootlessTunTestPacketRouter.Target.DROP, ipv6);
        if (RootlessTunTestPacketRouter.rejection(fragmented, fragmented.length)
                != RootlessTunTestPacketRouter.Reason.FRAGMENT) throw new AssertionError("fragment reason");
        if (RootlessTunTestPacketRouter.rejection(badChecksum, badChecksum.length)
                != RootlessTunTestPacketRouter.Reason.IP_CHECKSUM) throw new AssertionError("checksum reason");
        if (RootlessTunTestPacketRouter.rejection(ipv6, ipv6.length)
                != RootlessTunTestPacketRouter.Reason.NON_IPV4) throw new AssertionError("IPv6 reason");
        byte[] nonce = new byte[16];
        Arrays.fill(nonce, (byte) 37);
        byte[] probe = Arrays.copyOf(udp("198.18.1.10"), 45);
        probe[3] = 45;
        probe[22] = (byte)(43434 >>> 8);
        probe[23] = (byte)43434;
        probe[25] = 25;
        System.arraycopy(nonce, 0, probe, 28, 16);
        probe[44] = 0;
        checksum(probe);
        if (RootlessTunTestPacketRouter.probeIndex(probe, probe.length, 0xA601, nonce) != 0)
            throw new AssertionError("valid probe rejected");
        if (RootlessTunTestPacketRouter.probeIndex(probe, probe.length, 0xA602, nonce) != -1)
            throw new AssertionError("foreign source port accepted");
        probe[44] = 1;
        if (RootlessTunTestPacketRouter.probeIndex(probe, probe.length, 0xA601, nonce) != -1)
            throw new AssertionError("wrong destination accepted");
        probe[44] = 0;
        probe[28] ^= 1;
        if (RootlessTunTestPacketRouter.probeIndex(probe, probe.length, 0xA601, nonce) != -1)
            throw new AssertionError("foreign batch accepted");
        System.out.println("Rootless TUN test packet router PASS");
    }

    private static byte[] udp(String destination) {
        byte[] packet = new byte[31];
        packet[0] = 0x45;
        packet[2] = 0;
        packet[3] = (byte) packet.length;
        packet[8] = 64;
        packet[9] = 17;
        packet[12] = 10;
        packet[13] = (byte) 253;
        packet[14] = 0;
        packet[15] = 1;
        String[] octets = destination.split("\\.");
        for (int i = 0; i < 4; i++) packet[16 + i] = (byte) Integer.parseInt(octets[i]);
        packet[20] = (byte) 0xA6;
        packet[21] = 0x01;
        packet[22] = (byte) 0xA6;
        packet[23] = 0x02;
        packet[24] = 0;
        packet[25] = 11;
        packet[26] = 0;
        packet[27] = 0;
        packet[28] = 1;
        packet[29] = 2;
        packet[30] = 3;
        checksum(packet);
        return packet;
    }

    private static byte[] tcp(String destination) {
        byte[] packet = udp(destination);
        packet[9] = 6;
        checksum(packet);
        return packet;
    }

    private static void checksum(byte[] packet) {
        packet[10] = 0;
        packet[11] = 0;
        long sum = 0;
        for (int i = 0; i < 20; i += 2) {
            sum += ((packet[i] & 0xff) << 8) | (packet[i + 1] & 0xff);
        }
        while ((sum >>> 16) != 0) sum = (sum & 0xffffL) + (sum >>> 16);
        int value = (int) (~sum) & 0xffff;
        packet[10] = (byte) (value >>> 8);
        packet[11] = (byte) value;
    }

    private static void expect(RootlessTunTestPacketRouter.Target expected, byte[] packet) {
        RootlessTunTestPacketRouter.Target actual =
                RootlessTunTestPacketRouter.select(packet, packet.length);
        if (actual != expected) {
            throw new AssertionError("expected " + expected + " but got " + actual
                    + " packet=" + Arrays.toString(packet));
        }
    }
}
