package com.yooshastan.wonheeproxy;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Offline transport exception contract for a future exact-owned runtime.
 * A candidate mark, route lookup or successful TCP probe is NOT authorization
 * to send private HTTP or install live firewall rules.
 */
final class RootTransportGuardPlan {
    static final String TAG = "WN_TRANSPORT_EXACT_V2";

    static final class Plan {
        final String device;
        final String uplink;
        final RootTcpProbeTarget endpoint;
        final int localPort;
        final long mark;
        final String chain;
        private final List<String> ruleArgs;

        private Plan(String device, String uplink, RootTcpProbeTarget endpoint,
                int localPort, long mark) {
            this.device = device;
            this.uplink = uplink;
            this.endpoint = endpoint;
            this.localPort = localPort;
            this.mark = mark;
            this.chain = endpoint.family == 4 ? RootMokaHomeFirewallPilotPlan.CHAIN4
                    : RootMokaHomeFirewallPilotPlan.CHAIN6;
            ruleArgs = Collections.unmodifiableList(Arrays.asList(
                    "-o", uplink, "-d", endpoint.address
                    + (endpoint.family == 4 ? "/32" : "/128"),
                    "-p", "udp", "--sport", Integer.toString(localPort),
                    "--dport", Integer.toString(endpoint.port),
                    "-m", "mark", "--mark", RootFirewallMark.display(mark) + "/0xffffffff",
                    "-m", "comment", "--comment", TAG + "_" + device,
                    "-j", "RETURN"));
        }

        List<String> insert() { return command("-I", true); }
        List<String> check() { return command("-C", false); }
        List<String> remove() { return command("-D", false); }

        private List<String> command(String operation, boolean position) {
            java.util.ArrayList<String> command = new java.util.ArrayList<>();
            command.add(endpoint.family == 4 ? "iptables" : "ip6tables");
            command.addAll(Arrays.asList("-w", "5", "-t", "filter", operation, chain));
            if (position) command.add("1");
            command.addAll(ruleArgs);
            return Collections.unmodifiableList(command);
        }

        // No live activation in this revision: independent live socket identity,
        // collision audit, rule ownership and rollback evidence remain mandatory.
        boolean activationAllowed() { return false; }

        @Override public String toString() {
            return "Transport proposal (IPv" + endpoint.family
                    + "); activation blocked; endpoint omitted";
        }
    }

    private RootTransportGuardPlan() { }

    /**
     * Compile a candidate from numeric peer endpoint and two route observations.
     * An unchanged underlay is necessary but not sufficient for live safety.
     * All other selected tunnel identities and nonzero marks must be supplied.
     */
    static Plan compile(String device, String endpoint, int localPort, long candidate,
            String unmarkedUplink, String markedUplink,
            Set<String> selectedDevices, Set<Long> otherMarks) {
        if (device == null || !device.matches("wnm[0-9a-f]{12}")
                || selectedDevices == null || !selectedDevices.contains(device)
                || otherMarks == null || candidate <= 0 || candidate > 0xffffffffL
                || (candidate & RootFirewallMark.ANDROID_PROTECTED_FROM_VPN) != 0
                || localPort < 1 || localPort > 65535
                || unmarkedUplink == null || !unmarkedUplink.equals(markedUplink)
                || !unmarkedUplink.matches("(?:rmnet|wlan|eth|usb)[A-Za-z0-9_.-]{0,10}")
                || selectedDevices.contains(unmarkedUplink)) {
            throw new IllegalArgumentException("Unsafe transport candidate.");
        }
        for (String selected : selectedDevices) {
            if (selected == null || !selected.matches("wnm[0-9a-f]{12}"))
                throw new IllegalArgumentException("Unverified tunnel identity.");
        }
        for (Long existing : otherMarks) {
            if (existing == null || existing <= 0 || existing > 0xffffffffL
                    || existing == candidate)
                throw new IllegalArgumentException("Conflicting or unknown transport mark.");
        }
        // The candidate cannot use Android's netId or standard permission bits.
        // This is a conservative syntactic check, not proof of vendor ownership.
        if ((candidate & 0x001fffffL) != 0)
            throw new IllegalArgumentException("Android mark bits overlap.");
        RootTcpProbeTarget target = RootTcpProbeTarget.parse(endpoint);
        try {
            java.net.InetAddress address = java.net.InetAddress.getByName(target.address);
            if (address.isAnyLocalAddress() || address.isLoopbackAddress()
                    || address.isMulticastAddress() || address.isLinkLocalAddress())
                throw new IllegalArgumentException("Invalid unicast peer endpoint.");
        } catch (java.net.UnknownHostException invalid) {
            throw new IllegalArgumentException("Invalid numeric peer endpoint.");
        }
        return new Plan(device, markedUplink, target, localPort, candidate);
    }

    /** Reject duplicate marks or interfaces before any future batch is journaled. */
    static boolean distinctBatch(List<Plan> plans) {
        if (plans == null || plans.isEmpty()) return false;
        Set<String> devices = new HashSet<>();
        Set<Long> marks = new HashSet<>();
        for (Plan p : plans) {
            if (p == null || !devices.add(p.device) || !marks.add(p.mark)) return false;
        }
        return true;
    }
}
