package com.yooshastan.wonheeproxy;

import android.content.Context;

import com.wireguard.android.util.RootShell;
import com.wireguard.android.util.ToolsInstaller;
import com.wireguard.config.Config;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Android root adapter for the isolated WireGuard transaction.
 *
 * NOT WIRED INTO PRODUCTION START/STOP. Constructing this adapter requires a
 * separate SafetyGate that checks a genuine dual-stack, no-leak, no-fallback
 * policy and protected physical WireGuard UDP endpoint before ANY mutation.
 * The project intentionally has no such gate implementation yet. It may not
 * be activated by Home selection, a debug flag or a shell property.
 *
 * This class never writes Android main/legacy routing tables, Android netd
 * fwmarks, mangle chains or system Private DNS. All mutations go through
 * the journal-first RootIsolatedWireGuardTransaction.
 */
final class RootIsolatedWireGuardKernelAdapter
        implements RootIsolatedWireGuardTransaction.Kernel {
    interface SafetyGate {
        void proveIsolatedUnderlayDnsAndFailClosed() throws Exception;
    }

    private static final Pattern ADDRESS = Pattern.compile(
            "^ip -([46]) addr add ([0-9A-Fa-f:.]+/(?:32|128)) dev (wnm[0-9a-f]{12})$");
    private static final Pattern ROUTE = Pattern.compile(
            "^ip -([46]) route add table (5100[0-7]) ([0-9A-Fa-f:.]+/[0-9]{1,3})"
                    + " dev (wnm[0-9a-f]{12})$");

    private final Context context;
    private final RootShell shell;
    private final ToolsInstaller tools;
    private final Map<String, Config> selected;
    private final SafetyGate safetyGate;
    private final Set<String> createdThisProcess = new HashSet<>();
    private final Map<String, String> createdIfindices = new HashMap<>();
    private boolean preflightApproved;

    RootIsolatedWireGuardKernelAdapter(Context context, RootShell shell,
            Map<String, Config> selected, SafetyGate safetyGate) {
        if (context == null || shell == null || selected == null
                || selected.isEmpty() || safetyGate == null) {
            throw new IllegalArgumentException("Complete safety gate and profiles required.");
        }
        this.context = context.getApplicationContext();
        this.shell = shell;
        // Android's root PATH does not generally expose wg or wg-quick.
        // Use the exact same bundled WireGuard CLI extraction as the
        // already-supported RootMultiKernelSession, never a KPM or a
        // device-wide system partition installation.
        this.tools = new ToolsInstaller(this.context, shell);
        this.selected = new HashMap<>(selected);
        for (Map.Entry<String, Config> entry : this.selected.entrySet()) {
            if (entry.getKey() == null
                    || !entry.getKey().matches("wnm[0-9a-f]{12}")
                    || entry.getValue() == null || entry.getValue().getPeers().size() != 1) {
                throw new IllegalArgumentException("Invalid isolated WireGuard profile.");
            }
        }
        this.safetyGate = safetyGate;
    }

    @Override public void requireActivationPreflight() throws Exception {
        preflightApproved = false;
        safetyGate.proveIsolatedUnderlayDnsAndFailClosed();
        shell.start();
        tools.ensureToolsAvailable();
        if (shell.run(null, "wg --version >/dev/null 2>&1") != 0
                || shell.run(null, "wg-quick --help >/dev/null 2>&1") != 0) {
            throw new IllegalStateException("WireGuard kernel tools not available.");
        }
        List<String> links = read("ip -o link show");
        for (String line : links) {
            if (line.matches(".*: (wnm[0-9a-f]{12}|wnhome0|wnair0)(@[^:]*)?:.*")) {
                throw new IllegalStateException("An existing Wonhee interface prevents isolated Start.");
            }
        }
        // Prior 12500-12999 policy (including the new UID plan) cannot be
        // adopted. The exact ownership journal is validated independently.
        for (int family : new int[]{4, 6}) {
            for (String line : read("ip -" + family + " rule show")) {
                if (line.matches("^12[5-9][0-9]{2}:.*")) {
                    throw new IllegalStateException("Reserved policy priority is occupied.");
                }
            }
            for (int table = 51000; table < 51008; table++) {
                if (!read("ip -" + family + " route show table " + table).isEmpty()) {
                    throw new IllegalStateException("Foreign or stale private table present.");
                }
            }
        }
        preflightApproved = true;
    }

    @Override public RootIsolatedWireGuardTransaction.Presence inspect(
            RootIsolatedWireGuardBootstrapPlan.Step step) throws Exception {
        if (step == null || !selected.containsKey(step.device)) {
            return RootIsolatedWireGuardTransaction.Presence.FOREIGN_OR_CHANGED;
        }
        RootIsolatedWireGuardKernelListing.Match link =
                RootIsolatedWireGuardKernelListing.interfaceKind(
                        linkReadback(step.device), step.device);
        if (link == RootIsolatedWireGuardKernelListing.Match.FOREIGN_OR_CHANGED
                || (createdThisProcess.contains(step.device)
                    && !sameNewKernelLink(step.device))) {
            return RootIsolatedWireGuardTransaction.Presence.FOREIGN_OR_CHANGED;
        }
        if (step.kind.equals("LINK_CREATE")) {
            if (link == RootIsolatedWireGuardKernelListing.Match.ABSENT) {
                return RootIsolatedWireGuardTransaction.Presence.ABSENT;
            }
            if (sameNewKernelLink(step.device) || publicKeyMatches(step.device)) {
                return RootIsolatedWireGuardTransaction.Presence.EXACT_OWNED;
            }
            return RootIsolatedWireGuardTransaction.Presence.FOREIGN_OR_CHANGED;
        }
        if (step.kind.equals("PEER_CONFIG")) {
            if (link == RootIsolatedWireGuardKernelListing.Match.ABSENT) {
                return RootIsolatedWireGuardTransaction.Presence.ABSENT;
            }
            List<String> peers = read("wg show " + step.device + " peers");
            if (peers.isEmpty() && (sameNewKernelLink(step.device)
                    || publicKeyMatches(step.device))) {
                return RootIsolatedWireGuardTransaction.Presence.ABSENT;
            }
            if (publicKeyMatches(step.device)
                    && peers.size() == 1
                    && expectedPeer(step.device).equals(peers.get(0).trim())) {
                return RootIsolatedWireGuardTransaction.Presence.EXACT_OWNED;
            }
            return RootIsolatedWireGuardTransaction.Presence.FOREIGN_OR_CHANGED;
        }
        if (link == RootIsolatedWireGuardKernelListing.Match.ABSENT) {
            return RootIsolatedWireGuardTransaction.Presence.ABSENT;
        }
        if (!sameNewKernelLink(step.device) && !publicKeyMatches(step.device)) {
            return RootIsolatedWireGuardTransaction.Presence.FOREIGN_OR_CHANGED;
        }
        RootIsolatedWireGuardKernelListing.Match match;
        if (step.kind.equals("LINK_UP")) {
            match = RootIsolatedWireGuardKernelListing.interfaceUp(
                    linkReadback(step.device), step.device);
        } else if (step.kind.equals("HOST_ADDRESS")) {
            Matcher p = ADDRESS.matcher(step.install);
            if (!p.matches() || !step.device.equals(p.group(3))) {
                return RootIsolatedWireGuardTransaction.Presence.FOREIGN_OR_CHANGED;
            }
            int family = Integer.parseInt(p.group(1));
            match = RootIsolatedWireGuardKernelListing.address(
                    String.join("\n", read("ip -" + family + " -o addr show dev "
                            + step.device)), family, p.group(2), step.device);
        } else if (step.kind.equals("PRIVATE_ROUTE")) {
            Matcher p = ROUTE.matcher(step.install);
            if (!p.matches() || !step.device.equals(p.group(4))) {
                return RootIsolatedWireGuardTransaction.Presence.FOREIGN_OR_CHANGED;
            }
            int family = Integer.parseInt(p.group(1));
            int table = Integer.parseInt(p.group(2));
            match = RootIsolatedWireGuardKernelListing.privateRoute(
                    String.join("\n", read("ip -" + family + " route show table "
                            + table)), family, p.group(3), step.device);
        } else {
            return RootIsolatedWireGuardTransaction.Presence.FOREIGN_OR_CHANGED;
        }
        return translate(match);
    }

    @Override public void apply(RootIsolatedWireGuardBootstrapPlan.Step step)
            throws Exception {
        if (!preflightApproved || !RootIsolatedWireGuardTransaction.safeStep(step)
                || !selected.containsKey(step.device)) {
            throw new IllegalStateException("Isolated startup is not authorized.");
        }
        if ("PEER_CONFIG".equals(step.kind)) {
            RootIsolatedWireGuardConfigHandoff.apply(
                    context, shell, step.device, selected.get(step.device));
        } else {
            // Only command shapes validated by the transaction are reachable.
            requireSuccess(step.install);
            if ("LINK_CREATE".equals(step.kind)) {
                // Bind the in-process pre-key create to a kernel ifindex.
                // A competing process cannot replace this named interface
                // and have us accidentally delete it by name alone.
                String ifindex = exactIfindex(step.device);
                createdIfindices.put(step.device, ifindex);
                createdThisProcess.add(step.device);
            }
        }
    }

    @Override public void undo(RootIsolatedWireGuardBootstrapPlan.Step step)
            throws Exception {
        if (!RootIsolatedWireGuardTransaction.safeStep(step)
                || !selected.containsKey(step.device)
                || inspect(step) != RootIsolatedWireGuardTransaction.Presence.EXACT_OWNED) {
            throw new IllegalStateException("No exact isolated kernel ownership.");
        }
        if ("PEER_CONFIG".equals(step.kind)) {
            // Delete ONLY the exact, pre-verified peer. Kernel private key
            // disappears when the owned link is deleted in the last stage.
            String peer = expectedPeer(step.device);
            if (!peer.matches("[A-Za-z0-9+/]{43}=")) {
                throw new IllegalStateException("Invalid WireGuard public key.");
            }
            requireSuccess("wg set " + step.device + " peer " + peer + " remove");
        } else {
            requireSuccess(step.inverse);
            if ("LINK_CREATE".equals(step.kind)) {
                createdThisProcess.remove(step.device);
                createdIfindices.remove(step.device);
            }
        }
    }

    private String exactIfindex(String device) throws Exception {
        List<String> values = read("cat /sys/class/net/" + device + "/ifindex");
        if (values.size() != 1 || !values.get(0).trim().matches("[0-9]{1,10}")) {
            throw new IllegalStateException("WireGuard kernel ifindex unreadable.");
        }
        return values.get(0).trim();
    }

    private boolean sameNewKernelLink(String device) {
        if (!createdThisProcess.contains(device)) return false;
        try {
            return createdIfindices.get(device).equals(exactIfindex(device));
        } catch (Exception changed) {
            return false;
        }
    }

    private String expectedPeer(String device) {
        return selected.get(device).getPeers().get(0)
                .getPublicKey().toBase64();
    }

    private boolean publicKeyMatches(String device) {
        try {
            List<String> keys = read("wg show " + device + " public-key");
            return keys.size() == 1
                    && selected.get(device).getInterface().getKeyPair()
                            .getPublicKey().toBase64().equals(keys.get(0).trim());
        } catch (Exception invalid) {
            return false;
        }
    }

    private String linkReadback(String device) throws Exception {
        List<String> result = new ArrayList<>();
        int status = shell.run(result, "ip -d -o link show dev " + device);
        if (status != 0) {
            // An interface may be absent or the inventory may have failed.
            // Distinguish only by a second root-readable existence test.
            if (shell.run(null, "test ! -d /sys/class/net/" + device) == 0) {
                return "";
            }
            throw new IllegalStateException("Kernel link identity unreadable.");
        }
        return String.join("\n", result);
    }

    private List<String> read(String command) throws Exception {
        List<String> result = new ArrayList<>();
        if (shell.run(result, command) != 0) {
            throw new IllegalStateException("Isolated kernel readback failed.");
        }
        return result;
    }

    private void requireSuccess(String command) throws Exception {
        if (shell.run(null, command) != 0) {
            throw new IllegalStateException("Isolated kernel operation failed.");
        }
    }

    private static RootIsolatedWireGuardTransaction.Presence translate(
            RootIsolatedWireGuardKernelListing.Match match) {
        switch (match) {
            case ABSENT:
                return RootIsolatedWireGuardTransaction.Presence.ABSENT;
            case EXACT:
                return RootIsolatedWireGuardTransaction.Presence.EXACT_OWNED;
            default:
                return RootIsolatedWireGuardTransaction.Presence.FOREIGN_OR_CHANGED;
        }
    }
}
