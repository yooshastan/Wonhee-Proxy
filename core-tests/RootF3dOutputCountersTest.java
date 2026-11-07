package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** Pure-Java counter parser tests; never run a root command or generate traffic. */
public final class RootF3dOutputCountersTest {
    private static void check(boolean ok, String description) {
        if (!ok) throw new AssertionError(description);
    }

    private static List<String> sample(long policyPkts, long firstPkts, long secondPkts) {
        return Arrays.asList(
                "Chain OUTPUT (policy ACCEPT " + policyPkts + " packets, 10394 bytes)",
                "    pkts      bytes target     prot opt in     out     source               destination",
                "      " + firstPkts + "       900 fw_OUTPUT all -- * *  ::/0 ::/0",
                "      " + secondPkts + "       102 DROP       all -- * * 2001:db8::/32 ::/0"
        );
    }

    public static void main(String[] args) {
        check(RootF3dOutputCounters.command(true)
                        .equals("ip6tables -t filter -n -v -x -L OUTPUT 2>/dev/null"),
                "IPv6 inventory command must only list existing counters");
        check(RootF3dOutputCounters.command(false)
                        .equals("iptables -t filter -n -v -x -L OUTPUT 2>/dev/null"),
                "IPv4 inventory command must be read-only");
        for (String cmd : Arrays.asList(RootF3dOutputCounters.command(true),
                RootF3dOutputCounters.command(false))) {
            check(!cmd.contains(" -Z") && !cmd.contains(" -A")
                            && !cmd.contains(" -I") && !cmd.contains(" -F")
                            && !cmd.contains(" -P"), "never mutate counters or rules");
        }

        RootF3dOutputCounters.Snapshot one =
                RootF3dOutputCounters.parse(0, sample(6, 2, 1));
        RootF3dOutputCounters.Snapshot two =
                RootF3dOutputCounters.parse(0, Arrays.asList(
                        "Chain OUTPUT (policy ACCEPT 9 packets, 10788 bytes)",
                        " pkts bytes target prot opt in out source destination",
                        "  4   1100 fw_OUTPUT all -- * * ::/0 ::/0",
                        "  2    150 DROP all -- * * 2001:db8::/32 ::/0"));
        check(one.readable && two.readable && one.ruleIdentities.size() == 2,
                "recognize standard long counter output");
        RootF3dOutputCounters.Comparison delta =
                RootF3dOutputCounters.compare(one, two);
        check(delta.status == RootF3dOutputCounters.Status.MOVED
                        && delta.advancedRules == 2 && delta.observedRules == 2
                        && delta.defaultPolicyIncrements == 3
                        && delta.sumRuleIncrements == 3,
                "compare existing counters only when rule layout remains identical");
        String text = delta.render("IPv6");
        check(text.contains("MOVED")
                        && text.contains("NOT a unique packet count")
                        && text.contains("does NOT identify")
                        && !text.contains("2001:db8::")
                        && !text.contains("fw_OUTPUT"),
                "sanitize all rule targets and IPv6 addresses");
        RootF3dOutputCounters.Snapshot same =
                RootF3dOutputCounters.parse(0, sample(6, 2, 1));
        check(RootF3dOutputCounters.compare(one, same).status
                        == RootF3dOutputCounters.Status.NO_MOVEMENT,
                "no counter increase should not be called proof of no OUTPUT traffic");

        List<String> reordered = new ArrayList<>(sample(6, 2, 1));
        Collections.swap(reordered, 2, 3);
        check(RootF3dOutputCounters.compare(one,
                        RootF3dOutputCounters.parse(0, reordered)).status
                        == RootF3dOutputCounters.Status.RULE_SET_CHANGED,
                "rule reorder invalidates counter comparison");
        check(RootF3dOutputCounters.compare(two, one).status
                        == RootF3dOutputCounters.Status.COUNTER_RESET,
                "counter decrease must not imply negative traffic");
        check(RootF3dOutputCounters.compare(one,
                        RootF3dOutputCounters.parse(1, sample(10, 3, 2))).status
                        == RootF3dOutputCounters.Status.UNAVAILABLE,
                "failed command is not a trusted observation");
        check(!RootF3dOutputCounters.parse(0,
                        Arrays.asList("permission denied")).readable,
                "unexpected command output must not be treated as zero");
        check(!RootF3dOutputCounters.parse(0, Collections.emptyList()).readable,
                "empty output is unavailable");
        check(!RootF3dOutputCounters.parse(0,
                        Arrays.asList("Chain INPUT (policy ACCEPT 1 packets, 2 bytes)")).readable,
                "other chain is not acceptable");
        check(RootF3dOutputCounters.parse(0,
                        Arrays.asList("Chain OUTPUT (policy DROP 0 packets, 0 bytes)",
                                "pkts bytes target prot opt in out source destination")).readable,
                "valid zero-rule built-in chain still has a policy header");

        System.out.println("RootF3dOutputCountersTest PASS");
    }
}
