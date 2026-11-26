package com.yooshastan.wonheeproxy;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public final class RootTransportGuardPlanTest {
    private static final String A = "wnm111111111111";
    private static final String B = "wnm222222222222";
    private static final Set<String> DEVICES = new HashSet<>(Arrays.asList(A, B));
    private static final long MARK = 0x00800000L;

    private static void check(boolean value) {
        if (!value) throw new AssertionError();
    }

    private static RootTransportGuardPlan.Plan compile(String device, String endpoint,
            int port, long mark, String first, String second, Set<Long> others) {
        return RootTransportGuardPlan.compile(device, endpoint, port, mark,
                first, second, DEVICES, others);
    }

    private static void refuses(Runnable test) {
        try { test.run(); } catch (IllegalArgumentException expected) { return; }
        throw new AssertionError("Unsafe candidate accepted");
    }

    public static void main(String[] args) {
        RootTransportGuardPlan.Plan v6 = compile(A, "[2001:db8::1]:51820",
                56739, MARK, "rmnet16", "rmnet16", Collections.emptySet());
        check(v6.insert().equals(Arrays.asList("ip6tables", "-w", "5", "-t", "filter",
                "-I", "WN_MOKA_HOME6", "1", "-o", "rmnet16", "-d", "2001:db8::1/128",
                "-p", "udp", "--sport", "56739", "--dport", "51820",
                "-m", "mark", "--mark", "0x800000/0xffffffff", "-m", "comment",
                "--comment", "WN_TRANSPORT_EXACT_V2_" + A, "-j", "RETURN")));
        check(v6.remove().get(5).equals("-D"));
        check(v6.check().get(5).equals("-C"));
        check(v6.insert().subList(8, v6.insert().size()).equals(
                v6.remove().subList(7, v6.remove().size())));
        check(!v6.activationAllowed());
        check(!v6.toString().contains("2001:db8"));
        RootTransportGuardPlan.Plan v4 = compile(B, "192.0.2.2:1637",
                41816, 0x01000000L, "wlan0", "wlan0", Collections.singleton(MARK));
        check(v4.insert().get(0).equals("iptables"));
        check(v4.insert().contains("192.0.2.2/32"));
        check(RootTransportGuardPlan.distinctBatch(Arrays.asList(v6, v4)));
        check(!RootTransportGuardPlan.distinctBatch(Arrays.asList(v6, v6)));
        RootTransportGuardPlan.Plan duplicateMark = compile(B, "192.0.2.2:1637",
                41816, MARK, "wlan0", "wlan0", Collections.emptySet());
        check(!RootTransportGuardPlan.distinctBatch(Arrays.asList(v6, duplicateMark)));
        refuses(() -> compile(A, "[2001:db8::1]:51820", 56739, MARK,
                "rmnet16", "rmnet17", Collections.emptySet()));
        refuses(() -> compile(A, "[2001:db8::1]:51820", 56739, MARK,
                B, B, Collections.emptySet()));
        refuses(() -> compile(A, "[2001:db8::1]:51820", 56739, MARK,
                "rmnet16", "rmnet16", Collections.singleton(MARK)));
        refuses(() -> compile(A, "[2001:db8::1]:51820", 56739, 0,
                "rmnet16", "rmnet16", Collections.emptySet()));
        refuses(() -> compile(A, "[2001:db8::1]:51820", 56739, 0x20000L,
                "rmnet16", "rmnet16", Collections.emptySet()));
        refuses(() -> compile(A, "[2001:db8::1]:51820", 56739, MARK | 1L,
                "rmnet16", "rmnet16", Collections.emptySet()));
        refuses(() -> compile(A, "example.org:51820", 56739, MARK,
                "rmnet16", "rmnet16", Collections.emptySet()));
        refuses(() -> compile(A, "[::1]:51820", 56739, MARK,
                "rmnet16", "rmnet16", Collections.emptySet()));
        refuses(() -> compile(A, "[fe80::1%wlan0]:51820", 56739, MARK,
                "rmnet16", "rmnet16", Collections.emptySet()));
        refuses(() -> compile(A, "[2001:db8::1]:51820", 0, MARK,
                "rmnet16", "rmnet16", Collections.emptySet()));
        refuses(() -> compile(A, "[2001:db8::1]:51820", 56739, MARK,
                "rmnet16;id", "rmnet16;id", Collections.emptySet()));
        System.out.println("RootTransportGuardPlanTest passed");
    }
}
