package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Exact-scope, non-executing firewall proposal for the Moka/Home pilot.
 *
 * Preparation never calls root or mutates Android. The proposed guard is
 * fail-closed for Moka UID on BOTH IP families. This intentionally means
 * Moka may have only one usable network destination while the pilot runs.
 * Do not activate until an independent kernel/packet/rollback adapter exists.
 */
final class RootMokaHomeFirewallPilotPlan {
    static final String HOST = "10.0.0.169";
    static final int PORT = 4533;
    static final String CHAIN4 = "WN_MOKA_HOME4";
    static final String CHAIN6 = "WN_MOKA_HOME6";
    static final String TAG4 = "WN_MOKA_HOME4_EXACT_V1";
    static final String TAG6 = "WN_MOKA_HOME6_EXACT_V1";

    static final class Step {
        final int family;
        final String kind;
        final String install;
        final String inverse;
        Step(int family, String kind, String install, String inverse) {
            this.family = family;
            this.kind = kind;
            this.install = install;
            this.inverse = inverse;
        }
    }

    static final class Plan {
        final int uid;
        final String homeDevice;
        final List<Step> steps;
        Plan(int uid, String homeDevice, List<Step> steps) {
            this.uid = uid;
            this.homeDevice = homeDevice;
            this.steps = Collections.unmodifiableList(new ArrayList<>(steps));
        }

        /** A simulator or static validator cannot authorize packet activation. */
        boolean activationAllowed() { return false; }

        String summary() {
            return "MOKA FIREWALL PLAN ONLY: " + steps.size()
                    + " exact proposed operations; IPv4 permits only "
                    + HOST + ":" + PORT + " on verified Home device; IPv6 "
                    + "and all other Moka output fail closed. "
                    + "No chains, OUTPUT hooks, UID routes or DNS changed.";
        }
    }

    private RootMokaHomeFirewallPilotPlan() { }

    static Plan compile(int uid, String homeDevice) {
        if (uid < 10000 || uid > 99999
                || homeDevice == null || !homeDevice.matches("wnm[0-9a-f]{12}")) {
            throw new IllegalArgumentException("Refuse unverified app UID or Home device.");
        }
        List<Step> steps = new ArrayList<>();
        for (int family : new int[]{4, 6}) {
            String bin = family == 4 ? "iptables" : "ip6tables";
            String chain = family == 4 ? CHAIN4 : CHAIN6;
            String tag = family == 4 ? TAG4 : TAG6;
            String base = bin + " -w -t filter ";
            steps.add(new Step(family, "CHAIN",
                    base + "-N " + chain, base + "-X " + chain));
            if (family == 4) {
                String allow = "-A " + chain + " -o " + homeDevice
                        + " -d " + HOST + "/32 -p tcp --dport " + PORT
                        + " -j RETURN";
                steps.add(new Step(family, "ALLOW_HOME_ONLY",
                        base + allow, base + allow.replace("-A ", "-D ")));
            }
            String deny = "-A " + chain + " -j REJECT";
            steps.add(new Step(family, "TERMINAL_DENY",
                    base + deny, base + deny.replace("-A ", "-D ")));
        }
        // A separate kernel adapter must verify both chains are populated,
        // the Android OUTPUT hook priority is safe, and BOTH families
        // are protected before any UID routing selector becomes visible.
        for (int family : new int[]{4, 6}) {
            String bin = family == 4 ? "iptables" : "ip6tables";
            String chain = family == 4 ? CHAIN4 : CHAIN6;
            String tag = family == 4 ? TAG4 : TAG6;
            String args = "-m owner --uid-owner " + uid
                    + " -m comment --comment " + tag + " -j " + chain;
            String base = bin + " -w -t filter ";
            steps.add(new Step(family, "OWNER_ANCHOR",
                    base + "-I OUTPUT 1 " + args,
                    base + "-D OUTPUT " + args));
        }
        return new Plan(uid, homeDevice, steps);
    }

    static boolean safeStep(Plan plan, Step step) {
        if (plan == null || step == null) return false;
        Plan canonical;
        try {
            canonical = compile(plan.uid, plan.homeDevice);
        } catch (IllegalArgumentException invalid) {
            return false;
        }
        for (Step allowed : canonical.steps) {
            if (allowed.family == step.family && allowed.kind.equals(step.kind)
                    && allowed.install.equals(step.install)
                    && allowed.inverse.equals(step.inverse)) return true;
        }
        return false;
    }
}
