package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** Pure Product F root OUTPUT-guard plan; no commands run by this class. */
final class RootFailClosedFirewallPlan {
    static final String LEDGER = "WN_FAIL_CLOSED_V1";
    static final String CHAIN4 = "WN_MULTI_GUARD4";
    static final String CHAIN6 = "WN_MULTI_GUARD6";
    static final String TAG4 = "WN_MULTI_GUARD4_ANCHOR";
    static final String TAG6 = "WN_MULTI_GUARD6_ANCHOR";

    static final class Tunnel {
        final String device;
        final String address;
        final int port;
        final long mark;
        final List<String> allowedIps;

        Tunnel(String device, String address, int port, long mark, List<String> allowedIps) {
            if (device == null || !device.matches("wnm[0-9a-f]{12}")
                    || address == null || !numericIp(address) || port < 1 || port > 65535
                    || mark < 1 || mark > 0xffffffffL || allowedIps == null) {
                throw new IllegalArgumentException("Invalid validated WireGuard transport exception.");
            }
            this.device = device;
            this.address = address;
            this.port = port;
            this.mark = mark;
            this.allowedIps = new ArrayList<>(allowedIps);
            for (String cidr : allowedIps) if (!validCidr(cidr)) {
                throw new IllegalArgumentException("Invalid selected WireGuard route.");
            }
        }
    }

    static final class Rule {
        final int family;
        final String args;

        Rule(int family, String args) {
            if ((family != 4 && family != 6) || args == null
                    || args.length() > 300 || !safeRule(family, args)) {
                throw new IllegalArgumentException("Unsafe firewall rule shape.");
            }
            this.family = family;
            this.args = args;
        }

        String prefix() { return (family == 4 ? "iptables" : "ip6tables") + " -w"; }
        String chain() { return family == 4 ? CHAIN4 : CHAIN6; }
        String add() { return prefix() + " -A " + chain() + " " + args; }
        String exists() { return prefix() + " -C " + chain() + " " + args; }
    }

    static final class Plan {
        final List<Rule> rules;

        Plan(List<Rule> rules) {
            if (rules.size() < 4 || rules.size() > 64) {
                throw new IllegalArgumentException("Guard rule count outside bounded range.");
            }
            boolean ipv4 = false, ipv6 = false;
            Set<String> unique = new LinkedHashSet<>();
            for (Rule rule : rules) {
                if (!unique.add(rule.family + "|" + rule.args)) {
                    throw new IllegalArgumentException("Duplicate firewall rule.");
                }
                if (rule.family == 4) ipv4 = true; else ipv6 = true;
            }
            if (!ipv4 || !ipv6 || !rules.get(rules.size() - 1).args.equals("-j REJECT")) {
                throw new IllegalArgumentException("Incomplete dual-stack guard.");
            }
            for (int family : new int[]{4, 6}) {
                int finalReject = 0;
                boolean terminated = false;
                for (Rule rule : rules) if (rule.family == family) {
                    if (terminated) throw new IllegalArgumentException("Rules after terminal reject.");
                    if (rule.args.equals("-j REJECT")) { finalReject++; terminated = true; }
                }
                if (finalReject != 1) throw new IllegalArgumentException("Guard needs one terminal reject.");
            }
            this.rules = Collections.unmodifiableList(new ArrayList<>(rules));
        }

        List<Rule> family(int family) {
            List<Rule> result = new ArrayList<>();
            for (Rule rule : rules) if (rule.family == family) result.add(rule);
            return result;
        }

        String encode() {
            StringBuilder result = new StringBuilder(LEDGER).append('\n');
            for (Rule rule : rules) result.append(rule.family).append('|').append(rule.args).append('\n');
            return result.toString();
        }
    }

    private RootFailClosedFirewallPlan() { }

    private static boolean safeRule(int family, String args) {
        if (args.equals("-o lo -j RETURN") || args.equals("-j REJECT")) return true;
        String ip = family == 4 ? "[0-9.]+" : "[0-9a-fA-F:.]+";
        String cidr = ip + "/[0-9]{1,3}";
        String device = "wnm[0-9a-f]{12}";
        return args.matches("-p udp -d " + ip + " --dport [0-9]{1,5} -m mark --mark 0x[0-9a-f]{1,8}/0xffffffff -j RETURN")
                || args.matches("-d " + cidr + " ! -o " + device + " -j REJECT")
                || args.matches("-o " + device + " -d " + cidr + " -j RETURN");
    }

    static String chain(int family) { return family == 4 ? CHAIN4 : CHAIN6; }
    static String tag(int family) { return family == 4 ? TAG4 : TAG6; }
    static String prefix(int family) { return family == 4 ? "iptables -w" : "ip6tables -w"; }
    static String anchorArgs(int family) {
        return "-m comment --comment " + tag(family) + " -j " + chain(family);
    }

    static boolean numericIp(String value) {
        if (value.contains(":")) return value.matches("[0-9a-fA-F:.]+") && !value.contains("%")
                && value.length() <= 45;
        if (!value.matches("[0-9]{1,3}(\\.[0-9]{1,3}){3}")) return false;
        for (String part : value.split("\\.")) if (Integer.parseInt(part) > 255) return false;
        return true;
    }

    private static boolean validCidr(String cidr) {
        if (cidr == null || !cidr.contains("/")) return false;
        String[] parts = cidr.split("/", -1);
        if (parts.length != 2 || !numericIp(parts[0]) || !parts[1].matches("[0-9]{1,3}")) return false;
        int bits = Integer.parseInt(parts[1]);
        return bits >= 0 && bits <= (parts[0].contains(":") ? 128 : 32);
    }

    static Plan build(List<Tunnel> tunnels) {
        if (tunnels == null || tunnels.isEmpty() || tunnels.size() > 8) {
            throw new IllegalArgumentException("Select one to eight identity-verified tunnels.");
        }
        List<Rule> all = new ArrayList<>();
        Set<String> devices = new LinkedHashSet<>();
        Set<Long> marks = new LinkedHashSet<>();
        Set<String> exactUdpEndpoints = new LinkedHashSet<>();
        for (Tunnel tunnel : tunnels) {
            if (!devices.add(tunnel.device)
                    || !exactUdpEndpoints.add(tunnel.address + "|" + tunnel.port)) {
                throw new IllegalArgumentException("Every selected tunnel needs a unique "
                        + "device and numeric UDP endpoint tuple.");
            }
            if (!marks.add(tunnel.mark)
                    && tunnel.mark != RootFirewallMark.ANDROID_PROTECTED_FROM_VPN) {
                throw new IllegalArgumentException("Shared non-Android fwmark refused.");
            }
        }
        for (int family : new int[]{4, 6}) {
            all.add(new Rule(family, "-o lo -j RETURN"));
            // Exact UDP endpoint and mark are the ONLY physical-underlay
            // exception. There is deliberately no broad fwmark bypass.
            for (Tunnel tunnel : tunnels) if ((tunnel.address.contains(":") ? 6 : 4) == family) {
                all.add(new Rule(family, "-p udp -d " + tunnel.address + " --dport "
                        + tunnel.port + " -m mark --mark 0x" + Long.toHexString(tunnel.mark)
                        + "/0xffffffff -j RETURN"));
            }
            // A private/Home split destination must not fall back through the
            // Internet tunnel's /0 route when Home is disconnected.
            for (Tunnel tunnel : tunnels) for (String route : tunnel.allowedIps) {
                if (route.equals("0.0.0.0/0") || route.equals("::/0")
                        || (route.contains(":") ? 6 : 4) != family) continue;
                all.add(new Rule(family, "-d " + route + " ! -o " + tunnel.device + " -j REJECT"));
            }
            for (Tunnel tunnel : tunnels) for (String route : tunnel.allowedIps) {
                if ((route.contains(":") ? 6 : 4) != family) continue;
                all.add(new Rule(family, "-o " + tunnel.device + " -d " + route + " -j RETURN"));
            }
            all.add(new Rule(family, "-j REJECT"));
        }
        return new Plan(all);
    }

    static Plan decode(String text) {
        if (text == null || text.length() > 20000 || !text.startsWith(LEDGER + "\n")) {
            throw new IllegalArgumentException("Unknown guard ownership ledger.");
        }
        List<Rule> rules = new ArrayList<>();
        for (String line : text.substring(LEDGER.length() + 1).split("\n")) {
            if (line.isEmpty()) continue;
            if (line.length() < 5 || line.charAt(1) != '|') {
                throw new IllegalArgumentException("Invalid guard ledger entry.");
            }
            int family = line.charAt(0) == '4' ? 4 : line.charAt(0) == '6' ? 6 : 0;
            rules.add(new Rule(family, line.substring(2)));
        }
        return new Plan(rules);
    }
}
