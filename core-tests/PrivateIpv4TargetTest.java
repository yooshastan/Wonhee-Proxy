package com.yooshastan.wonheeproxy;

import java.util.Arrays;

public final class PrivateIpv4TargetTest {
    private static void accept(String host, String port, int expectedPort) {
        PrivateIpv4Target target = PrivateIpv4Target.parse(host, port);
        if (target.port != expectedPort) throw new AssertionError("wrong port");
        byte[] address = target.addressBytes();
        address[0] = 0;
        if (Arrays.equals(address, target.addressBytes()))
            throw new AssertionError("address bytes must not be mutable");
    }
    private static void reject(String host, String port) {
        try {
            PrivateIpv4Target.parse(host, port);
            throw new AssertionError("accepted unsafe target");
        } catch (IllegalArgumentException expected) { }
    }
    public static void main(String[] args) {
        accept("10.77.0.1", "4533", 4533);
        accept(" 172.16.0.1 ", "80", 80);
        accept("172.31.255.254", "443", 443);
        accept("192.168.1.1", "65535", 65535);
        reject("8.8.8.8", "443");
        reject("172.32.0.1", "443");
        reject("127.0.0.1", "443");
        reject("100.100.100.100", "443");
        reject("10.1.1.256", "80");
        reject("10.01.1.2", "80");
        reject("10.1.1.1", "0");
        reject("10.1.1.1", "65536");
        reject("hostname.example", "443");
        reject("::1", "443");
        reject("10.1.1.1", "abc");
        System.out.println("PASS PrivateIpv4TargetTest");
    }
}
