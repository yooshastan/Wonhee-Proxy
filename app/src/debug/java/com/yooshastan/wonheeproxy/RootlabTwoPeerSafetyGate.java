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
 * Limited, side-by-side DEBUG-only gate for a link-only pilot.
 *
 * It proves that the *new* private tables have no kernel rule selectors that
 * could steer Android application traffic into them. Unlike the full product
 * kill switch, this does NOT claim network leak protection for apps, DNS, or
 * routing after a subsequent external network change. Accordingly the lab
 * MUST NOT create any UID rules, packet marks or system/main routes.
 *
 * Full production activation remains forbidden.
 */
final class RootlabTwoPeerSafetyGate
        implements RootIsolatedWireGuardKernelAdapter.SafetyGate {
    private final Context app;
    private final RootShell shell;

    RootlabTwoPeerSafetyGate(Context app, RootShell shell) {
        if (app == null || shell == null) {
            throw new IllegalArgumentException("Missing lab safety prerequisites.");
        }
        this.app = app.getApplicationContext();
        this.shell = shell;
    }

    @Override public void proveIsolatedUnderlayDnsAndFailClosed() throws Exception {
        // No changes to Private DNS are ever made by the pilot.
        String privateDns = Settings.Global.getString(
                app.getContentResolver(), "private_dns_mode");
        if (!"off".equals(privateDns)) {
            throw new IllegalStateException(
                    "Android Private DNS must remain OFF for this device.");
        }
        // A separate Android VpnService could capture WireGuard's root
        // endpoint sockets and produce a false "independent" handshake.
        // Refuse a simultaneous Android VPN even though this lab does not
        // itself request Android VPN permission.
        ConnectivityManager connectivity = (ConnectivityManager)
                app.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (connectivity == null) {
            throw new IllegalStateException("Android network service unavailable.");
        }
        Network active = connectivity.getActiveNetwork();
        NetworkCapabilities caps = active == null
                ? null : connectivity.getNetworkCapabilities(active);
        if (caps == null || caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
            throw new IllegalStateException(
                    "Use an active physical network without another Android VPN.");
        }
        if (RootIsolatedWireGuardPreferencesJournal.pendingOrUnknown(app)
                || RootIsolatedUidPolicyPreferencesJournal.pendingOrUnknown(app)
                || RootlabDetachedMokaFirewall.pendingOrUnknown(app)
                || RootlabMokaIpv6OutputTest.pendingOrUnknown(app)) {
            throw new IllegalStateException(
                    "An old isolated ownership journal needs exact recovery.");
        }
        shell.start();
        for (int family : new int[]{4, 6}) {
            List<String> rules = new ArrayList<>();
            if (shell.run(rules, "ip -" + family + " rule show") != 0
                    || rules.isEmpty()) {
                throw new IllegalStateException(
                        "Cannot inventory Android's IPv" + family + " policy.");
            }
            for (String rule : rules) {
                String normalized = rule.trim().replaceAll("\\s+", " ");
                if (normalized.matches("(?s).*\\b(?:lookup|table) 5100[0-7]\\b.*")
                        || normalized.matches("12[5-9][0-9]{2}:.*")) {
                    throw new IllegalStateException(
                            "UID or foreign policy already references reserved routing.");
                }
            }
        }
        // Physical endpoint UDP egress and handshake must be separately
        // verified AFTER the links exist; an empty private table alone is
        // insufficient proof of endpoint reachability.
    }
}
