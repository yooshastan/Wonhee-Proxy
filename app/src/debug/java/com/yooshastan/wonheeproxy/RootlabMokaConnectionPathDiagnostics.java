package com.yooshastan.wonheeproxy;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.provider.Settings;

import com.wireguard.android.util.RootShell;
import java.util.ArrayList;
import java.util.List;

/**
 * Read-only snapshot of the Moka/Home path, taken while the observed app
 * connection is attempted. No root network writes, packet probes, DNS
 * requests, packet capture, socket binding, or private peer data.
 *
 * Synthetic UID route-get is NOT evidence of actual app socket routing.
 * Firewall counts may be zero if the app never made a TCP attempt, if an
 * Android network selector rejected it, or if the packet bypassed the hook.
 */
final class RootlabMokaConnectionPathDiagnostics {
    private static final String MOKA = "com.mokamusic.player";
    private static final String CHROME = "com.android.chrome";
    private static final String BRAVE = "com.brave.browser_nightly";
    private final Context app;

    RootlabMokaConnectionPathDiagnostics(Context context) {
        app = context.getApplicationContext();
    }

    private static List<String> read(RootShell shell, String command)
            throws Exception {
        List<String> output = new ArrayList<>();
        if (shell.run(output, command) != 0) return null;
        return output;
    }

    private static String join(List<String> lines) {
        return lines == null ? null : String.join("\n", lines);
    }

    private static int packageUid(RootShell shell, String pkg)
            throws Exception {
        List<String> lines = read(shell, "pm list packages -U " + pkg);
        if (lines == null) return -1;
        String prefix = "package:" + pkg + " uid:";
        int uid = -1;
        for (String line : lines) {
            String candidate = line.trim();
            if (!candidate.startsWith(prefix)) continue;
            String tail = candidate.substring(prefix.length()).trim();
            if (!tail.matches("[1-9][0-9]{4,6}")) return -1;
            if (uid != -1) return -1;
            uid = Integer.parseInt(tail);
        }
        return uid;
    }

    private static String route(RootShell shell, int uid, String homeDevice)
            throws Exception {
        if (uid < 10000) return "APP_UID_NOT_VISIBLE";
        List<String> output = read(shell,
                "ip -4 route get 10.0.0.169 uid " + uid);
        return RootMokaConnectionPathEvidence.syntheticRoute(
                join(output), homeDevice);
    }

    private static String counts(RootShell shell, String family,
            String chain, String target) throws Exception {
        List<String> output = read(shell,
                family + " -w -t filter -L " + chain + " -n -v -x");
        if (output == null) return "UNAVAILABLE_OR_CHAIN_ABSENT";
        try {
            RootMokaIpv6CounterParser.Counts count =
                    RootMokaIpv6CounterParser.target(join(output), target);
            return count.packets + " packets / " + count.bytes + " bytes";
        } catch (IllegalArgumentException absent) {
            return "MISSING_OR_AMBIGUOUS";
        }
    }

    private static String activeTransport(Context app) {
        ConnectivityManager manager = (ConnectivityManager)
                app.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (manager == null) return "UNAVAILABLE";
        Network active = manager.getActiveNetwork();
        NetworkCapabilities caps = active == null ? null
                : manager.getNetworkCapabilities(active);
        if (caps == null) return "UNAVAILABLE";
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return "VPN";
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR))
            return "CELLULAR";
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) return "WIFI";
        return "OTHER";
    }

    private static String socketStates(RootShell shell) throws Exception {
        // Summarize only TCP states for the fixed private endpoint; never
        // export arbitrary sockets, remote IPs/ports, app names or tokens.
        List<String> lines = read(shell, "ss -tn");
        if (lines == null) return "SOCKET_INVENTORY_UNAVAILABLE";
        int matches = 0;
        StringBuilder states = new StringBuilder();
        for (String line : lines) {
            if (!line.contains("10.0.0.169:4533")
                    && !line.contains("10.0.0.169%")) continue;
            if (matches++ >= 12) break;
            String[] fields = line.trim().split("\\s+");
            if (fields.length > 0 && fields[0].matches("[A-Za-z0-9_-]{3,24}")) {
                if (states.length() > 0) states.append(", ");
                states.append(fields[0]);
            }
        }
        return matches == 0 ? "NONE_VISIBLE_AT_SNAPSHOT"
                : "VISIBLE_ENDPOINT_TCP_STATES=" + states;
    }

    String inspect(String homeDevice) throws Exception {
        String expectedHome = homeDevice != null
                && homeDevice.matches("wnm[0-9a-f]{12}") ? homeDevice : null;
        RootlabMokaHomeUidSelector selector =
                new RootlabMokaHomeUidSelector(app);
        boolean journal = RootlabMokaHomeUidSelector.pendingOrUnknown(app);
        String last = selector.lastOutcome();

        RootShell shell = new RootShell(app);
        shell.start();

        int mokaUid = packageUid(shell, MOKA);
        int chromeUid = packageUid(shell, CHROME);
        int braveUid = packageUid(shell, BRAVE);

        List<String> rules = read(shell, "ip -4 rule show");
        RootMokaHomeUidRuleEvidence.Snapshot rule = rules == null
                || mokaUid < 10000 ? null
                : RootMokaHomeUidRuleEvidence.inspect(join(rules), mokaUid);
        String ruleState = RootMokaConnectionPathEvidence.selectorState(
                journal, rule, last);

        StringBuilder out = new StringBuilder(
                "WONHEE 0.15.75 - MOKA/BROWSER CONNECTION PATH (READ ONLY)\n");
        out.append("Android active transport: ")
                .append(activeTransport(app)).append('\n');
        out.append("Android Private DNS: ")
                .append(Settings.Global.getString(
                        app.getContentResolver(), "private_dns_mode"))
                .append('\n');
        out.append("Last Moka UID selector outcome: ").append(last).append('\n');
        out.append("UID selector ownership journal: ")
                .append(journal ? "PRESENT_OR_UNKNOWN" : "ABSENT").append('\n');
        out.append("Live selector evidence: ").append(ruleState).append('\n');
        out.append("Home profile device: ")
                .append(expectedHome == null ? "UNVERIFIED" : "KNOWN_FROM_PROFILE")
                .append('\n');
        if (expectedHome != null) {
            List<String> homeTable = read(shell, "ip -4 route show table 51002");
            if (homeTable != null) {
                RootMokaHomeTerminalRouteEvidence.Snapshot home =
                        RootMokaHomeTerminalRouteEvidence.inspect(
                                join(homeTable), expectedHome);
                out.append("Home private /32: ")
                        .append(home.homePresent ? "PRESENT" : "ABSENT")
                        .append("; high-metric unreachable: ")
                        .append(home.terminalPresent ? "PRESENT" : "ABSENT")
                        .append("; route collision: ")
                        .append(home.collision ? "YES" : "NO")
                        .append('\n');
                List<String> device = read(shell,
                        "ip -o link show dev " + expectedHome);
                out.append("Home interface: ")
                        .append(device == null || device.isEmpty()
                                ? "NOT_VISIBLE" : "PRESENT")
                        .append('\n');
            } else {
                out.append("Home private table: UNAVAILABLE\n");
            }
        }
        out.append("Moka UID ").append(mokaUid)
                .append(" synthetic route: ")
                .append(route(shell, mokaUid, expectedHome)).append('\n');
        out.append("Chrome UID ").append(chromeUid)
                .append(" synthetic route: ")
                .append(route(shell, chromeUid, expectedHome)).append('\n');
        out.append("Brave Nightly UID ").append(braveUid)
                .append(" synthetic route: ")
                .append(route(shell, braveUid, expectedHome)).append('\n');

        out.append("Moka IPv4 OUTPUT hook: ")
                .append(counts(shell, "iptables", "OUTPUT",
                        RootMokaHomeFirewallPilotPlan.CHAIN4)).append('\n');
        out.append("Moka IPv4 Home TCP/4533 RETURN: ")
                .append(counts(shell, "iptables",
                        RootMokaHomeFirewallPilotPlan.CHAIN4, "RETURN"))
                .append('\n');
        out.append("Moka IPv4 REJECT: ")
                .append(counts(shell, "iptables",
                        RootMokaHomeFirewallPilotPlan.CHAIN4, "REJECT"))
                .append('\n');
        out.append("Moka IPv6 OUTPUT hook: ")
                .append(counts(shell, "ip6tables", "OUTPUT",
                        RootMokaHomeFirewallPilotPlan.CHAIN6)).append('\n');
        out.append("Target TCP sockets: ")
                .append(socketStates(shell)).append('\n');
        out.append("No packets, app routing, DNS or VPN configurations "
                + "were changed. Zero counters or no visible sockets "
                + "do NOT prove that no connection was attempted. "
                + "A synthetic route is NOT a Moka or browser packet test. "
                + "If a UID rule is present without a journal, preserve "
                + "diagnostics and do not clear app data. "
                + "Use Exact-owned Safe Stop after live tests.");
        return out.toString();
    }
}
