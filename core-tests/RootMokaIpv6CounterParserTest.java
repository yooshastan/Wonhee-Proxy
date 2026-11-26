package com.yooshastan.wonheeproxy;

public final class RootMokaIpv6CounterParserTest {
    static int assertions;
    private static void check(boolean ok, String message) {
        assertions++;
        if (!ok) throw new AssertionError(message);
    }
    private static void refuses(String text, String target) {
        boolean rejected = false;
        try { RootMokaIpv6CounterParser.target(text, target); }
        catch (IllegalArgumentException expected) { rejected = true; }
        check(rejected, "Expected refusal");
    }
    public static void main(String[] args) {
        String chain = "Chain WN_MOKA_HOME6 (1 references)\n"
                + "    pkts      bytes target     prot opt in     out source destination\n"
                + "       7       560 REJECT     all      *      *   ::/0 ::/0 reject-with icmp6-port-unreachable\n";
        var c = RootMokaIpv6CounterParser.target(chain, "REJECT");
        check(c.packets == 7 && c.bytes == 560, "Exact reject counters");
        var h = RootMokaIpv6CounterParser.target(
                "Chain OUTPUT (policy ACCEPT 400 packets, 32000 bytes)\n"
                + "  12  2048 WN_MOKA_HOME6 all -- * * ::/0 ::/0 owner UID match 10300\n",
                "WN_MOKA_HOME6");
        check(h.packets == 12 && h.bytes == 2048, "Hook counter");
        check(RootMokaIpv6CounterParser.delta(7, 9) == 2, "Delta");
        check(RootMokaIpv6CounterParser.delta(9, 7) == -1, "Reset unknown");
        refuses(chain, "WN_MOKA_HOME6");
        refuses("1 2 REJECT all -- * * ::/0 ::/0\n3 4 REJECT all -- * * ::/0 ::/0", "REJECT");
        refuses("18446744073709551615 2 REJECT all -- * * ::/0 ::/0", "REJECT");
        refuses("0 0 ACCEPT all -- * * ::/0 ::/0", "REJECT");
        System.out.println("MOKA_IPV6_COUNTER_PARSER " + assertions + " PASS");
    }
}
