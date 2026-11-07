package com.yooshastan.wonheeproxy;

import java.net.InetAddress;
import java.util.List;

/**
 * Pure, conservative first-match simulator for the exact Batch F owned chain grammar.
 *
 * Does not inspect or transmit packets. Does not evaluate other apps' firewall
 * chains, Android netd policy, NAT, interface availability or actual socket marks.
 * This is diagnostic-only and must never be interpreted as proof of egress.
 */
final class RootGuardFlowModel {
    enum Result { RETURN, REJECT, UNKNOWN }

    private RootGuardFlowModel() { }

    static final class Flow {
        final int family;
        final String destination;
        final String out;
        final String protocol;
        final int port;
        final long mark;

        Flow(int family, String destination, String out, String protocol, int port, long mark) {
            if ((family != 4 && family != 6) || destination == null || out == null
                    || protocol == null || port < 0 || port > 65535 || mark < 0
                    || mark > 0xffffffffL) {
                throw new IllegalArgumentException("Invalid modeled packet shape.");
            }
            this.family = family;
            this.destination = destination;
            this.out = out;
            this.protocol = protocol;
            this.port = port;
            this.mark = mark;
        }
    }

    private static boolean cidrContains(String cidr, String destination) {
        try {
            String[] fields = cidr.split("/", -1);
            if (fields.length != 2 || !RootFailClosedFirewallPlan.numericIp(fields[0])
                    || !RootFailClosedFirewallPlan.numericIp(destination)) return false;
            byte[] network = InetAddress.getByName(fields[0]).getAddress();
            byte[] address = InetAddress.getByName(destination).getAddress();
            if (network.length != address.length) return false;
            int bits = Integer.parseInt(fields[1]);
            if (bits < 0 || bits > network.length * 8) return false;
            for (int bit = 0; bit < bits; bit++) {
                int mask = 1 << (7 - bit % 8);
                if ((network[bit / 8] & mask) != (address[bit / 8] & mask)) return false;
            }
            return true;
        } catch (Exception invalid) {
            return false;
        }
    }

    static Result evaluate(RootFailClosedFirewallPlan.Plan plan, Flow flow) {
        if (plan == null || flow == null) return Result.UNKNOWN;
        for (RootFailClosedFirewallPlan.Rule rule : plan.family(flow.family)) {
            final String args = rule.args;
            if ("-o lo -j RETURN".equals(args)) {
                if ("lo".equals(flow.out)) return Result.RETURN;
            } else if ("-j REJECT".equals(args)) {
                return Result.REJECT;
            } else if (args.startsWith("-p udp -d ") && args.endsWith(" -j RETURN")) {
                // The current grammar is an exact marked UDP endpoint exception.
                String[] parts = args.split(" ");
                // A TCP/ICMP flow does not match an earlier UDP-only rule;
                // it must continue through later tunnel or terminal rules.
                if (parts.length != 12
                        || !parts[0].equals("-p") || !parts[1].equals("udp")
                        || !parts[2].equals("-d")
                        || !parts[4].equals("--dport") || !parts[6].equals("-m")
                        || !parts[7].equals("mark") || !parts[8].equals("--mark")
                        || !parts[10].equals("-j")) return Result.UNKNOWN;
                String[] marked = parts[9].split("/", -1);
                if (marked.length != 2 || !marked[1].equals("0xffffffff")) {
                    return Result.UNKNOWN;
                }
                try {
                    if ("udp".equals(flow.protocol)
                            && parts[3].equals(flow.destination)
                            && Integer.parseInt(parts[5]) == flow.port
                            && Long.parseLong(marked[0].substring(2), 16) == flow.mark) {
                        return Result.RETURN;
                    }
                } catch (RuntimeException invalid) {
                    return Result.UNKNOWN;
                }
            } else if (args.startsWith("-d ") && args.endsWith(" -j REJECT")) {
                String[] parts = args.split(" ");
                if (parts.length != 7 || !parts[2].equals("!") || !parts[3].equals("-o")
                        || !parts[5].equals("-j")) return Result.UNKNOWN;
                if (cidrContains(parts[1], flow.destination)
                        && !parts[4].equals(flow.out)) return Result.REJECT;
            } else if (args.startsWith("-o ") && args.endsWith(" -j RETURN")) {
                String[] parts = args.split(" ");
                if (parts.length != 6 || !parts[2].equals("-d") || !parts[4].equals("-j")) {
                    return Result.UNKNOWN;
                }
                if (parts[1].equals(flow.out) && cidrContains(parts[3], flow.destination)) {
                    return Result.RETURN;
                }
            } else {
                return Result.UNKNOWN;
            }
        }
        return Result.UNKNOWN; // Refuse an incomplete/unknown plan rather than infer ALLOW.
    }

    static String preview(RootFailClosedFirewallPlan.Plan plan, String underlay,
            String home, String internet) {
        if (plan == null || underlay == null
                || !underlay.matches("(wlan|rmnet|eth|usb|clat)[A-Za-z0-9_.-]*")
                || home == null || !home.matches("wnm[0-9a-f]{12}")
                || internet == null || !internet.matches("wnm[0-9a-f]{12}")) {
            return "GUARD FLOW MODEL UNAVAILABLE — selected interfaces are not verified.";
        }
        Result dhcp = evaluate(plan, new Flow(4, "255.255.255.255", underlay, "udp", 67, 0));
        Result validation = evaluate(plan, new Flow(4, "1.1.1.1", underlay, "tcp", 80, 0));
        Result dns = evaluate(plan, new Flow(4, "1.1.1.1", underlay, "udp", 53, 0));
        Result ipv6 = evaluate(plan, new Flow(6, "ff02::2", underlay, "icmpv6", 0, 0));
        Result publicTunnel = evaluate(plan, new Flow(4, "1.1.1.1", internet, "tcp", 443, 0));
        Result homeTunnel = evaluate(plan, new Flow(4, "10.0.0.169", home, "tcp", 4533, 0));
        return "BATCH F — HYPOTHETICAL CONTROL-PLANE IMPACT (NO PACKETS SENT)\n"
                + "Underlay candidate: " + underlay + "\n"
                + "DHCPv4 UDP/67 on underlay: " + dhcp + "\n"
                + "HTTP captive-portal validation on underlay: " + validation + "\n"
                + "Plain DNS UDP/53 on underlay: " + dns + "\n"
                + "IPv6 router solicitation on underlay: " + ipv6 + "\n"
                + "Public HTTPS through selected Internet tunnel: " + publicTunnel + "\n"
                + "Navidrome TCP over selected HOME tunnel (example only): " + homeTunnel + "\n"
                + "A REJECT here means THIS prototype's chain would reject the "
                + "modeled unprotected flow. It does not prove Android needs that "
                + "flow, nor the actual packet path. Existing firewall/netd "
                + "behavior and dynamic endpoint changes remain untested. "
                + "Batch F activation is PAUSED after the connectivity incident.";
    }
}
