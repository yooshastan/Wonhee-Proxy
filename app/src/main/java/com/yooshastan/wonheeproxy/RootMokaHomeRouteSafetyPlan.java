package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Non-executing Home-only routing contract for the first Moka pilot.
 *
 * A Linux policy-rule lookup can fall through to Android's main table if a
 * selected private table has no matching route. A firewall RETURN is not
 * a terminal permit, and a route to the Home interface does not prove that
 * packets arrived there. This plan therefore NEVER authorizes activation.
 */
final class RootMokaHomeRouteSafetyPlan {
    static final String TARGET = "10.0.0.169/32";
    static final String HOST = "10.0.0.169";
    static final int PORT = 4533;
    static final int TABLE = 51002;
    static final int PRIORITY = 12700;

    static final class Gate {
        final String name;
        final boolean passed;
        Gate(String name, boolean passed) {
            this.name = name;
            this.passed = passed;
        }
    }
    static final class Plan {
        final int uid;
        final String homeDevice;
        final List<Gate> gates;
        final String candidateSelector;
        final String candidateTerminal;
        Plan(int uid, String homeDevice, List<Gate> gates,
                String candidateSelector, String candidateTerminal) {
            this.uid = uid;
            this.homeDevice = homeDevice;
            this.gates = Collections.unmodifiableList(new ArrayList<>(gates));
            this.candidateSelector = candidateSelector;
            this.candidateTerminal = candidateTerminal;
        }
        boolean activationAllowed() { return false; }
        String summary() {
            return "MOKA HOME ROUTE PLAN: exact UID " + uid + ", destination "
                    + HOST + ":" + PORT + ", private table " + TABLE
                    + "; no app/UID selection was installed.";
        }
    }

    private RootMokaHomeRouteSafetyPlan() { }

    static Plan compile(int uid, String homeDevice) {
        if (uid < 10000 || uid > 99999 || homeDevice == null
                || !homeDevice.matches("wnm[0-9a-f]{12}")) {
            throw new IllegalArgumentException("Invalid Moka UID or Home device.");
        }
        String selector = "ip -4 rule add pref " + PRIORITY
                + " iif lo uidrange " + uid + "-" + uid
                + " to " + TARGET + " lookup " + TABLE;
        // Future exact-owned, high-metric destination terminal requires
        // independent kernel syntax/no-fallback tests. Not executable here.
        String terminal = "ip -4 route add unreachable " + TARGET
                + " table " + TABLE + " metric 42700";
        List<Gate> gates = new ArrayList<>();
        gates.add(new Gate("EXACT_HOME_LINK_IDENTITY", false));
        gates.add(new Gate("IPV4_MOKA_TERMINAL_FIREWALL", false));
        gates.add(new Gate("IPV6_MOKA_TERMINAL_FIREWALL", false));
        gates.add(new Gate("NO_ANDROID_OUTPUT_BYPASS", false));
        gates.add(new Gate("HOME_DESTINATION_SPECIFIC_UNREACHABLE", false));
        gates.add(new Gate("NO_CELLULAR_FALLTHROUGH_ON_HOME_LOSS", false));
        gates.add(new Gate("ANDROID_UID_RULE_PRECEDENCE", false));
        gates.add(new Gate("DNS_AND_ENDPOINT_UNDERLAY", false));
        gates.add(new Gate("DURABLE_EXACT_INVERSE_RECOVERY", false));
        gates.add(new Gate("TCP_PORT_4533_SCOPE", false));
        return new Plan(uid, homeDevice, gates, selector, terminal);
    }

    /**
     * Rules deliberately have no working activation path. A missing Home
     * tunnel MUST block the service rather than returning to Android's
     * unprotected cellular routes.
     */
    static String evaluate(boolean homeUp, boolean exactUid, boolean dest,
            boolean tcpPort, boolean v4Firewall, boolean v6Firewall,
            boolean unreachableTerminal, boolean routingProof,
            boolean recoveryProof) {
        if (!exactUid || !dest || !tcpPort) return "REFUSE_SCOPE";
        if (!v4Firewall || !v6Firewall) return "REFUSE_DUAL_STACK";
        if (!unreachableTerminal) return "REFUSE_CELLULAR_FALLTHROUGH";
        if (!routingProof || !recoveryProof) return "REFUSE_UNPROVEN_OWNERSHIP";
        return homeUp ? "STILL_LOCKED_DEVICE_PACKET_PROOF"
                : "BLOCK_HOME_UNREACHABLE";
    }
}
