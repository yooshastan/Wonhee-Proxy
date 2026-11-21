package com.yooshastan.wonheeproxy;

import android.content.Context;
import android.content.SharedPreferences;
import com.wireguard.android.util.RootShell;
import java.util.ArrayList;
import java.util.List;

/**
 * Debug-only first LIVE hook experiment: IPv6 filter OUTPUT, Moka UID only.
 *
 * Requires previously journaled, exact detached chains. No IPv4 hook, UID
 * routing, DNS, or mark writes. The attached IPv6 chain rejects Moka IPv6,
 * therefore user MUST explicitly opt in and use Safe Stop after testing.
 *
 * Write-ahead before inserting the sole hook. Recovery never clears unknown
 * or foreign firewall rules and always precedes detached-chain deletion.
 */
final class RootlabMokaIpv6OutputTest {
    private static final String PREF = "wonhee_rootlab_moka_ipv6_hook_v1";
    private static final String KEY = "pending";
    private static final String VERSION = "WMH6V1";
    private static final String SNAPSHOT_PACKETS = "last_ipv6_reject_packets";
    private static final String SNAPSHOT_BYTES = "last_ipv6_reject_bytes";
    private static final String FIRST_PID = "attached_pid";

    private final Context app;
    RootlabMokaIpv6OutputTest(Context context) {
        app = context.getApplicationContext();
    }

    static boolean pendingOrUnknown(Context context) {
        try {
            return context.getApplicationContext()
                    .getSharedPreferences(PREF, Context.MODE_PRIVATE).contains(KEY);
        } catch (RuntimeException unknown) {
            return true;
        }
    }

    private SharedPreferences prefs() {
        return app.getSharedPreferences(PREF, Context.MODE_PRIVATE);
    }

    private RootMokaHomeFirewallPilotPlan.Plan planFromJournal() {
        String encoded = prefs().getString(KEY, null);
        if (encoded == null) return null;
        String[] fields = encoded.split("\\|", -1);
        if (fields.length != 3 || !VERSION.equals(fields[0])
                || !fields[1].matches("[1-9][0-9]{4}")
                || !fields[2].matches("wnm[0-9a-f]{12}")) {
            throw new IllegalStateException(
                    "Unknown Moka IPv6 OUTPUT journal; do not clear app data.");
        }
        return RootMokaHomeFirewallPilotPlan.compile(
                Integer.parseInt(fields[1]), fields[2]);
    }

    private void intent(RootMokaHomeFirewallPilotPlan.Plan plan) {
        String encoded = VERSION + "|" + plan.uid + "|" + plan.homeDevice;
        if (!prefs().edit().putString(KEY, encoded).commit()
                || !encoded.equals(prefs().getString(KEY, null))) {
            throw new IllegalStateException("Unable to commit IPv6 OUTPUT intent.");
        }
    }

    private void clear() {
        if (!prefs().edit().remove(KEY)
                .remove(SNAPSHOT_PACKETS).remove(SNAPSHOT_BYTES)
                .remove(FIRST_PID).commit() || prefs().contains(KEY)) {
            throw new IllegalStateException("IPv6 OUTPUT journal clear failed.");
        }
    }

    private static RootMokaHomeFirewallPilotPlan.Step hook(
            RootMokaHomeFirewallPilotPlan.Plan plan) {
        RootMokaHomeFirewallPilotTransaction.validate(plan);
        for (RootMokaHomeFirewallPilotPlan.Step step : plan.steps) {
            if (step.family == 6 && "OWNER_ANCHOR".equals(step.kind)
                    && RootMokaHomeFirewallPilotPlan.safeStep(plan, step)) {
                return step;
            }
        }
        throw new IllegalStateException("Missing canonical IPv6 owner hook.");
    }

    private static List<String> output(RootShell shell) throws Exception {
        List<String> lines = new ArrayList<>();
        if (shell.run(lines, "ip6tables -w -t filter -S OUTPUT") != 0
                || lines.isEmpty()) {
            throw new IllegalStateException("Cannot inspect IPv6 OUTPUT.");
        }
        return lines;
    }

    /**
     * Refuse any unexpected reference to the reserved IPv6 chain,
     * even if a semantically matching -C rule is also present.
     */
    private static int exactReferences(RootShell shell,
            RootMokaHomeFirewallPilotPlan.Plan plan) throws Exception {
        RootMokaHomeFirewallPilotPlan.Step step = hook(plan);
        String chain = RootMokaHomeFirewallPilotPlan.CHAIN6;
        String tag = RootMokaHomeFirewallPilotPlan.TAG6;
        int exactCount = 0;
        for (String line : output(shell)) {
            boolean ref = line.contains(" -j " + chain)
                    || line.contains(" -g " + chain);
            boolean tagged = line.contains(tag);
            if (!ref && !tagged) continue;
            // Require exact match of the canonical rule shape; no
            // unknown OUTPUT jumps may be treated as Wonhee-owned.
            String normalized = line.trim().replace("\"", "")
                    .replaceAll("\\s+", " ");
            String expected = step.install
                    .replace("ip6tables -w -t filter -I OUTPUT 1 ",
                            "-A OUTPUT ");
            if (!normalized.equals(expected)) {
                throw new IllegalStateException(
                        "Foreign/changed IPv6 OUTPUT hook: leave journal intact.");
            }
            exactCount++;
        }
        if (exactCount > 1) {
            throw new IllegalStateException("Duplicate IPv6 OUTPUT owner hooks.");
        }
        return exactCount;
    }

    /** Only used after exact -S and canonical shape checks. */
    private static boolean exactHookExists(RootShell shell,
            RootMokaHomeFirewallPilotPlan.Plan plan) throws Exception {
        int refs = exactReferences(shell, plan);
        if (refs == 0) return false;
        RootMokaHomeFirewallPilotPlan.Step step = hook(plan);
        return shell.run(null, step.inverse.replace(
                " -D OUTPUT ", " -C OUTPUT ") + " >/dev/null 2>&1") == 0;
    }

    /**
     * A separate dual-stack hook test may verify this exact installed IPv6
     * prerequisite without mutating counters or installing new firewall rules.
     */
    boolean exactAttached(int uid, String device) throws Exception {
        RootMokaHomeFirewallPilotPlan.Plan persisted = planFromJournal();
        if (persisted == null || persisted.uid != uid
                || !persisted.homeDevice.equals(device)) return false;
        RootShell shell = new RootShell(app);
        shell.start();
        return exactHookExists(shell, persisted);
    }

    String attach(int uid, String device) throws Exception {
        if (pendingOrUnknown(app)) {
            return "IPv6 HOOK REFUSED: a prior owner journal needs Safe Stop.";
        }
        RootMokaHomeFirewallPilotPlan.Plan plan =
                RootMokaHomeFirewallPilotPlan.compile(uid, device);
        if (!new RootlabDetachedMokaFirewall(app)
                .exactStagingPresent(uid, device)) {
            return "IPv6 HOOK REFUSED: both detached chains must be fully "
                    + "journaled and exact before attaching.";
        }
        RootShell shell = new RootShell(app);
        shell.start();
        if (exactReferences(shell, plan) != 0) {
            return "IPv6 HOOK REFUSED: reserved OUTPUT hook is already occupied.";
        }
        // No Android UID routing is active in this pilot. IPv6 Moka sockets
        // will be blocked; IPv4 and every other application remain unchanged.
        RootMokaHomeFirewallPilotPlan.Step step = hook(plan);
        try {
            intent(plan);
            if (shell.run(null, step.install) != 0 || !exactHookExists(shell, plan)) {
                throw new IllegalStateException("Hook install/readback failed.");
            }
            // Optional process-restart indicator; failure to persist it
            // never invalidates the already durable hook ownership journal.
            prefs().edit().putInt(FIRST_PID, android.os.Process.myPid()).commit();
            return "MOKA IPv6 OUTPUT HOOK VERIFIED: exact UID " + uid
                    + " owner hook installed. Moka IPv6 OUTPUT is REJECTED "
                    + "via its verified private chain; IPv4, UID routing, DNS, "
                    + "and other apps unchanged. NOT dual-stack fail-closed; "
                    + "do not use this as a VPN. Run Exact-owned Safe Stop.";
        } catch (Exception error) {
            String cleanup = recover();
            return "IPv6 HOOK TEST FAILED (" + error.getClass().getSimpleName()
                    + "); " + cleanup;
        }
    }

    /**
     * Read-only packet evidence. No -Z/-F, packet injection, DNS changes or
     * app launch. User opens Moka and attempts a normal connection between
     * two readings. Distinguishes observed packet hits from full protection.
     */
    String readCounters() throws Exception {
        RootMokaHomeFirewallPilotPlan.Plan plan = planFromJournal();
        if (plan == null) {
            return "MOKA IPv6 COUNTERS REFUSED: no active hook journal. "
                    + "Attach the Moka IPv6 guard first.";
        }
        RootShell shell = new RootShell(app);
        shell.start();
        if (!exactHookExists(shell, plan)
                || !new RootlabDetachedMokaFirewall(app)
                        .exactStagingPresentWithVerifiedIpv6Hook(plan.uid, plan.homeDevice)) {
            return "MOKA IPv6 COUNTERS REFUSED: missing or altered exact-owned "
                    + "hook/chain. Use Exact-owned Safe Stop; no counters reset.";
        }
        List<String> outputList = new ArrayList<>();
        List<String> chainList = new ArrayList<>();
        if (shell.run(outputList, "ip6tables -w -t filter -L OUTPUT -nvx") != 0
                || shell.run(chainList, "ip6tables -w -t filter -L "
                    + RootMokaHomeFirewallPilotPlan.CHAIN6 + " -nvx") != 0) {
            return "MOKA IPv6 COUNTERS UNAVAILABLE: read-only ip6tables listing "
                    + "failed; no firewall state modified.";
        }
        RootMokaIpv6CounterParser.Counts hookCounts =
                RootMokaIpv6CounterParser.target(
                        String.join("\n", outputList),
                        RootMokaHomeFirewallPilotPlan.CHAIN6);
        RootMokaIpv6CounterParser.Counts rejectCounts =
                RootMokaIpv6CounterParser.target(
                        String.join("\n", chainList), "REJECT");
        boolean prior = prefs().contains(SNAPSHOT_PACKETS)
                && prefs().contains(SNAPSHOT_BYTES);
        long oldPackets = prefs().getLong(SNAPSHOT_PACKETS, 0);
        long oldBytes = prefs().getLong(SNAPSHOT_BYTES, 0);
        long deltaPkts = prior ? RootMokaIpv6CounterParser.delta(
                oldPackets, rejectCounts.packets) : -1;
        long deltaBytes = prior ? RootMokaIpv6CounterParser.delta(
                oldBytes, rejectCounts.bytes) : -1;
        if (!prefs().edit().putLong(SNAPSHOT_PACKETS, rejectCounts.packets)
                .putLong(SNAPSHOT_BYTES, rejectCounts.bytes).commit()) {
            return "MOKA IPv6 COUNTERS READ BUT BASELINE SAVE FAILED; "
                    + "no kernel state modified; retry after inspecting journal.";
        }
        int attachedPid = prefs().getInt(FIRST_PID, 0);
        int nowPid = android.os.Process.myPid();
        return "MOKA IPv6 PACKET COUNTERS (READ ONLY)\n"
                + "Exact hook UID: " + plan.uid + "\n"
                + "IPv6 OUTPUT owner hook: " + hookCounts.packets
                + " packets, " + hookCounts.bytes + " bytes\n"
                + "Moka IPv6 private REJECT: " + rejectCounts.packets
                + " packets, " + rejectCounts.bytes + " bytes\n"
                + (deltaPkts < 0 || deltaBytes < 0
                    ? "DELTA: baseline established or counters reset; "
                            + "no increment claim\n"
                    : "SINCE LAST READING: +" + deltaPkts + " rejected packets, +"
                            + deltaBytes + " bytes\n")
                + (attachedPid != 0 && attachedPid != nowPid
                    ? "PROCESS RESTART INDICATOR: app PID differs from hook "
                            + "attachment; exact hook still verified\n"
                    : "PROCESS RESTART INDICATOR: same or unknown app PID\n")
                + "Counts are cumulative and cannot identify a specific "
                + "packet or prove IPv4/IPv6 leak protection. "
                + "No -Z counters reset, no DNS/routing/firewall changes. "
                + "Use Exact-owned Safe Stop.";
    }

    String recover() throws Exception {
        RootMokaHomeFirewallPilotPlan.Plan plan = planFromJournal();
        if (plan == null) return "MOKA IPv6 OUTPUT: no journaled hook.";
        RootShell shell = new RootShell(app);
        shell.start();
        try {
            int references = exactReferences(shell, plan);
            if (references == 1) {
                if (!exactHookExists(shell, plan)
                        || shell.run(null, hook(plan).inverse) != 0) {
                    throw new IllegalStateException("Exact IPv6 hook removal failed.");
                }
            }
            if (exactReferences(shell, plan) != 0) {
                throw new IllegalStateException("IPv6 hook remains attached.");
            }
            clear();
            return "MOKA IPv6 OUTPUT CLEAN_STOPPED; hook journal=0; "
                    + "no reserved OUTPUT reference remains.";
        } catch (Exception uncertain) {
            return "MOKA IPv6 OUTPUT RECOVERY PAUSED; journal retained. "
                    + "Do not uninstall, clear data or update RootLab.";
        }
    }
}
