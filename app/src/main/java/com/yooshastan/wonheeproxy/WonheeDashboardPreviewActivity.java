package com.yooshastan.wonheeproxy;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.pm.PackageManager;
import android.content.SharedPreferences;
import android.content.Intent;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.List;

/**
 * First-stage consumer dashboard preview. READ-ONLY status + navigation
 * to existing, tested connection/recovery and profile-management screens.
 *
 * Never alters root/firewall/DNS/tunnels and never claims an Android VPN
 * indicator or working full-device fail-closed kill switch.
 */
public final class WonheeDashboardPreviewActivity extends Activity {
    private static final int BACKGROUND = 0xff15101e;
    private static final int SURFACE = 0xff2b2038;
    private static final int SURFACE_ALT = 0xff372845;
    private static final int PINK = 0xffffaddb;
    private static final int LAVENDER = 0xffd2c1ff;
    private static final int WHITE = 0xfffff7fd;
    private static final int MUTED = 0xffc9bed2;
    private static final long REFRESH_MS = 8_000L;
    private static final String DNS_CHECKPOINT_PREFS = "wonhee-dns-checkpoint-v1";
    private static final String DNS_CHECKPOINT_KEY = "aggregate-only";
    private static final String ROOT_NOTIFICATION_PREFS = "wonhee_root_traffic_notification";
    private static final int NOTIFICATION_PERMISSION_REQUEST = 8452;

    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Runnable refresh = this::refreshSnapshot;
    private final List<SecureTunnelProfileStore.Profile> profiles = new ArrayList<>();
    private RootMultiKernelSession session;
    private RootMultiKernelSession.RootTrafficSnapshot lastSnapshot;
    private final RootDashboardTelemetry traffic = new RootDashboardTelemetry();
    private TunnelTrafficRates.Result liveRates;
    private boolean dnsDetailsExpanded;
    private int relaySeenPid = -1;
    private long relaySeenBlocked = -1;
    private String relayCounterEvent = "Awaiting verified relay counters";
    private LinearLayout content;
    private LinearLayout navigation;
    private boolean visible;
    private int tab;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        session = RootMultiKernelSession.get(this);
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(BACKGROUND);
        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setPadding(dp(18), dp(18), dp(18), dp(30));
        scroll.addView(page);
        setContentView(scroll);

        TextView name = text(page, "✦ WONHEE PROXY", 24, PINK);
        name.setContentDescription("Wonhee Proxy");
        text(page, "Candy Pink  •  Connection dashboard", 12, MUTED);
        text(page, "Live status is read-only; network changes remain in Safe Controls.",
                12, LAVENDER);
        navigation = new LinearLayout(this);
        navigation.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams tabs = new LinearLayout.LayoutParams(-1, -2);
        tabs.topMargin = dp(14);
        page.addView(navigation, tabs);

        content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        page.addView(content, new LinearLayout.LayoutParams(-1, -2));
        render();
    }

    @Override protected void onResume() {
        super.onResume();
        visible = true;
        traffic.reset();
        liveRates = null;
        loadSavedProfiles();
        refreshSnapshot();
    }

    @Override protected void onPause() {
        visible = false;
        traffic.reset();
        liveRates = null;
        handler.removeCallbacks(refresh);
        super.onPause();
    }

    private void loadSavedProfiles() {
        profiles.clear();
        try {
            profiles.addAll(new SecureTunnelProfileStore(this).load());
        } catch (Exception unavailable) {
            // Do not claim zero saved profiles when encrypted storage is unavailable.
            profileStoreError = true;
            render();
            return;
        }
        profileStoreError = false;
        render();
    }

    private boolean profileStoreError;

    private void refreshSnapshot() {
        if (!visible) return;
        handler.removeCallbacks(refresh);
        session.readRootTrafficSnapshot(snapshot -> {
            if (!visible || isFinishing() || isDestroyed()) return;
            lastSnapshot = snapshot;
            observeRelayCounterContinuity(snapshot);
            liveRates = snapshot == null ? traffic.observe(0, false, 0, 0, 0, 0)
                    : traffic.observe(SystemClock.elapsedRealtime(),
                            snapshot.countersAvailable,
                            snapshot.verifiedTunnels, snapshot.presentTunnels,
                            snapshot.received, snapshot.sent);
            render();
            handler.postDelayed(refresh, REFRESH_MS);
        });
    }

    /** Display-only interpretation. Never restores or changes DNS state. */
    private void observeRelayCounterContinuity(
            RootMultiKernelSession.RootTrafficSnapshot snapshot) {
        if (snapshot == null || !snapshot.dnsVerified
                || snapshot.dnsCounters == null) {
            relayCounterEvent = "Relay counters unavailable; continuity unknown";
            return;
        }
        RootDnsCounters now = snapshot.dnsCounters;
        if (relaySeenPid < 2) {
            relayCounterEvent = "Current relay observed; no earlier local sample";
        } else if (relaySeenPid != now.pid) {
            relayCounterEvent = "Relay PID changed — new session; lifetime counts reset";
        } else if (relaySeenBlocked > now.blocked) {
            relayCounterEvent = "Blocked counter decreased — verify relay identity";
        } else {
            relayCounterEvent = "Same verified relay; current lifetime counters";
        }
        relaySeenPid = now.pid;
        relaySeenBlocked = now.blocked;
    }

    private void render() {
        if (content == null) return;
        navigation.removeAllViews();
        String[] tabs = {"Status", "Tunnels", "DNS", "Activity"};
        for (int i = 0; i < tabs.length; i++) {
            final int next = i;
            Button button = new Button(this);
            button.setAllCaps(false);
            button.setText(tabs[i]);
            button.setTextSize(12);
            button.setTextColor(i == tab ? BACKGROUND : WHITE);
            button.setBackground(tint(i == tab ? PINK : SURFACE_ALT, 13));
            button.setMinHeight(dp(48));
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, dp(52), 1f);
            lp.setMargins(dp(2), 0, dp(2), dp(10));
            navigation.addView(button, lp);
            button.setOnClickListener(v -> { tab = next; render(); });
        }

        content.removeAllViews();
        switch (tab) {
            case 0: home(); break;
            case 1: profileTab(); break;
            case 2: protectionTab(); break;
            default: activityTab();
        }
        // Navigation to Safe Controls belongs to the Status recovery card only.
        // All other tabs remain read-only; no duplicate footer link.
    }

    /** Observed root counters only; these figures are not system VPN statistics. */
    private String throughputLine() {
        RootMultiKernelSession.RootTrafficSnapshot snapshot = lastSnapshot;
        if (snapshot == null || !snapshot.countersAvailable
                || snapshot.verifiedTunnels != snapshot.presentTunnels) {
            return "↓ unavailable   ↑ unavailable";
        }
        return liveRates == null ? "↓ measuring   ↑ measuring"
                : "↓ " + TunnelTrafficRates.formatSpeed(liveRates.downloadMbps)
                + "   ↑ " + TunnelTrafficRates.formatSpeed(liveRates.uploadMbps);
    }

    private void showLiveSignals() {
        LinearLayout group = card(content);
        text(group, "LIVE SIGNALS", 15, PINK);
        text(group, throughputLine(), 20, WHITE);
        text(group, "Combined verified WireGuard tunnel speeds · updates while visible. "
                + "Not device-wide traffic and not per-profile throughput.", 12, MUTED);
        RootMultiKernelSession.RootTrafficSnapshot snapshot = lastSnapshot;
        boolean verified = snapshot != null && snapshot.dnsVerified
                && snapshot.trackerEnabled && snapshot.blocked != null;
        text(group, verified ? snapshot.blocked + " blocked DNS replies"
                : "Blocked DNS replies: " + blockedCount(), 18,
                verified ? LAVENDER : MUTED);
        text(group, "DNS: " + dnsState() + "  ·  Filtering: "
                + (snapshot == null || !snapshot.dnsVerified ? "unverified"
                        : snapshot.trackerEnabled ? "enabled" : "off"),
                13, verified ? WHITE : MUTED);
        text(group, "Blocked total belongs to the current verified DNS relay lifetime.",
                12, MUTED);
        showNotificationControl(group);
    }

    private boolean wantsNotification() {
        return getSharedPreferences(ROOT_NOTIFICATION_PREFS, Context.MODE_PRIVATE)
                .getBoolean("enabled", false);
    }

    private boolean hasNotificationPermission() {
        return Build.VERSION.SDK_INT < 33 || checkSelfPermission(
                android.Manifest.permission.POST_NOTIFICATIONS)
                == PackageManager.PERMISSION_GRANTED;
    }

    private void showNotificationControl(LinearLayout group) {
        button(group, wantsNotification()
                        ? "Disable persistent speed + blocked DNS notification"
                        : "Enable persistent speed + blocked DNS notification",
                this::toggleNotification);
        text(group, wantsNotification()
                        ? "Requested: Android may restrict foreground notifications."
                        : "Optional. Only runs while verified kernel tunnels are active.",
                12, MUTED);
    }

    private void toggleNotification() {
        if (wantsNotification()) {
            getSharedPreferences(ROOT_NOTIFICATION_PREFS, Context.MODE_PRIVATE)
                    .edit().putBoolean("enabled", false).apply();
            RootMultiTrafficNotificationService.stop(this);
            render();
            return;
        }
        if (!hasNotificationPermission()) {
            if (Build.VERSION.SDK_INT >= 33) {
                requestPermissions(new String[]{
                        android.Manifest.permission.POST_NOTIFICATIONS
                }, NOTIFICATION_PERMISSION_REQUEST);
            }
            return;
        }
        enableNotification();
    }

    private void enableNotification() {
        // Same opt-in preference as Advanced Controls. Do not touch the VPN stack.
        getSharedPreferences(ROOT_NOTIFICATION_PREFS, Context.MODE_PRIVATE)
                .edit().putBoolean("enabled", true).apply();
        RootMultiTrafficNotificationService.startIfPossible(this);
        render();
    }

    @Override public void onRequestPermissionsResult(int requestCode,
            String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode != NOTIFICATION_PERMISSION_REQUEST) return;
        if (grantResults.length > 0
                && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
            enableNotification();
        } else {
            new AlertDialog.Builder(this)
                    .setTitle("Notification permission unavailable")
                    .setMessage("Wonhee will not display a persistent status notification "
                            + "without your permission. VPN, routing and DNS remain "
                            + "unchanged. You can enable notifications in Android settings.")
                    .setPositiveButton("OK", null).show();
        }
    }

    private void home() {
        LinearLayout hero = card(content);
        text(hero, "CONNECTION OVERVIEW", 12, LAVENDER);
        RootMultiKernelSession.RootTrafficSnapshot snapshot = lastSnapshot;
        String status = "Checking local root tunnel state…";
        if (snapshot != null && !snapshot.rootsAvailable) {
            status = "Root tunnel status unavailable";
        } else if (snapshot != null && snapshot.presentTunnels == 0) {
            status = "No saved-profile root tunnels detected";
        } else if (snapshot != null && snapshot.verifiedTunnels == snapshot.presentTunnels) {
            status = snapshot.verifiedTunnels + " verified root tunnel"
                    + (snapshot.verifiedTunnels == 1 ? "" : "s");
        } else if (snapshot != null) {
            status = "Attention: some tunnel identities unverified";
        }
        text(hero, status, 20, WHITE);
        if (snapshot != null && snapshot.rootsAvailable) {
            text(hero, "Identity-verified " + snapshot.verifiedTunnels + "/"
                    + snapshot.presentTunnels + " detected tunnel(s) · "
                    + (snapshot.countersAvailable ? "live counters available"
                            : "live counters not verified"), 13, LAVENDER);
        }
        text(hero, "Tunnel connection is not proof of full-device leak protection.", 12, MUTED);

        showLiveSignals();

        LinearLayout stack = card(content);
        text(stack, "YOUR CONNECTIONS", 15, PINK);
        if (profileStoreError) {
            text(stack, "Encrypted profiles unavailable. Check Android Keystore.", 13, MUTED);
        } else if (profiles.isEmpty()) {
            text(stack, "No profiles saved. Import a WireGuard configuration to begin.",
                    13, MUTED);
        } else {
            text(stack, profiles.size() + " saved · up to eight supported", 12, MUTED);
            int shown = Math.min(3, profiles.size());
            for (int i = 0; i < shown; i++) showProfile(stack, profiles.get(i));
            if (profiles.size() > shown) {
                text(stack, "+" + (profiles.size() - shown)
                        + " more saved profiles — see Profiles", 12, LAVENDER);
            }
        }

        LinearLayout protection = card(content);
        text(protection, "PROTECTION AT A GLANCE", 15, PINK);
        protectionRow(protection, "DNS relay (not a leak test)", dnsState());
        protectionRow(protection, "Ads & Trackers", blockState());
        protectionRow(protection, "DNS-port firewall", dnsFirewallLedgerState());
        protectionRow(protection, "All-traffic kill switch", killSwitchState());

        showRecoveryGuidance();

        // One safe destination appears in Connection Recovery Guidance above.
    }

    /** Guidance never tries to repair ownership or change the network itself. */
    private void showRecoveryGuidance() {
        LinearLayout group = card(content);
        text(group, "CONNECTION RECOVERY GUIDANCE", 15, PINK);
        RootMultiKernelSession.RootTrafficSnapshot s = lastSnapshot;
        String guidance;
        if (s == null || !s.rootsAvailable) {
            guidance = "Root status cannot be verified. Check USB ADB and run "
                    + "Read live kernel status in Safe Controls. Do not assume "
                    + "the tunnels or DNS rules are stopped.";
        } else if (s.presentTunnels > 0 && s.verifiedTunnels != s.presentTunnels) {
            guidance = "Some running tunnel identities are unverified. Avoid "
                    + "manual interface deletion or forced disconnect. Capture "
                    + "the read-only lifecycle and tunnel audit before Safe Stop.";
        } else if (s.presentTunnels == 0) {
            guidance = "No saved-profile tunnels detected. If a prior session "
                    + "was interrupted, run H.2a read-only lifecycle audit before "
                    + "starting a complete stack. This is not proof of clean stop.";
        } else if (!s.countersAvailable) {
            guidance = "Tunnel counters are not fully verified. Run F.2 passive "
                    + "health snapshot; inspect identities before attempting recovery.";
        } else if (!s.dnsVerified) {
            guidance = "Tunnels appear verified, but the DNS relay is not verified. "
                    + "Audit owned DNS rules and relay before restarting anything. "
                    + "Do not disable DNS protection solely for a diagnostic.";
        } else {
            guidance = "Tunnels and local DNS relay are verified at this snapshot. "
                    + "If browsing fails, use Connected but no Internet (read only) "
                    + "before the coordinated H.1 Safe Stop when practical.";
        }
        text(group, guidance, 13, WHITE);
        text(group, "Keep Android Private DNS OFF. All-traffic guard remains paused. "
                + "Never force a firewall flush or tunnel deletion.", 12, MUTED);
        button(group, "Safe Controls & Diagnostics",
                () -> startActivity(new Intent(this, RootMultiKernelActivity.class)));
    }

    private void profileTab() {
        LinearLayout group = card(content);
        text(group, "CONNECTION PROFILES", 16, PINK);
        text(group, "Use your own connection names. HOME, Work, Media and Internet are "
                + "optional roles, not required labels.", 13, MUTED);
        if (profileStoreError) {
            text(group, "Encrypted profile store could not be read.", 13, MUTED);
        } else if (profiles.isEmpty()) {
            text(group, "No saved profiles.", 13, MUTED);
        } else if (lastSnapshot == null || !lastSnapshot.rootsAvailable) {
            for (SecureTunnelProfileStore.Profile profile : profiles) {
                text(group, profile.name + " · live health unavailable", 14, MUTED);
            }
        } else {
            for (RootMultiKernelSession.TunnelStatus tunnel : lastSnapshot.tunnels) {
                LinearLayout item = card(group);
                text(item, tunnel.name, 16, PINK);
                text(item, !tunnel.present ? "Stopped / not detected"
                        : !tunnel.verified ? "Identity not verified — investigate"
                        : "Kernel identity verified · interface UP", 13,
                        tunnel.verified ? WHITE : MUTED);
                if (tunnel.verified) {
                    text(item, "Last handshake: " + tunnel.handshake
                            + " · idle is not a failure", 12, MUTED);
                    text(item, tunnel.received == null || tunnel.sent == null
                            ? "RX/TX unavailable"
                            : "RX " + TunnelTrafficRates.formatTotal(tunnel.received)
                              + " · TX " + TunnelTrafficRates.formatTotal(tunnel.sent),
                            13, WHITE);
                }
            }
            text(group, "These are periodic snapshots, not per-tunnel live "
                    + "speeds or end-to-end connection tests.", 12, MUTED);
        }
        button(group, "Import / edit saved VPN profiles",
                () -> startActivity(new Intent(this, VpnActivity.class)));
        text(group, "Current backend: one default exit plus compatible "
                + "destination-specific profiles. Overlapping routes are refused.", 12, MUTED);
    }

    private void protectionTab() {
        LinearLayout group = card(content);
        text(group, "DNS PROTECTION", 16, PINK);
        protectionRow(group, "Local DNS relay", dnsState());
        protectionRow(group, "Ad & tracker filtering", blockState());
        protectionRow(group, "DNS-port firewall", dnsFirewallLedgerState());
        button(group, dnsDetailsExpanded ? "Hide technical protection details"
                : "Show technical protection details", () -> {
            dnsDetailsExpanded = !dnsDetailsExpanded;
            render();
        });
        if (dnsDetailsExpanded) {
            protectionRow(group, "Connections",
                    lastSnapshot == null ? "Checking…"
                    : lastSnapshot.verifiedTunnels + " verified tunnels");
            protectionRow(group, "Routing", "Details in Safe Controls");
            protectionRow(group, "All-traffic kill switch", killSwitchState());
            text(group, "DNS-port enforcement is not an all-traffic kill switch. "
                    + "Live firewall verification requires a separate audit; "
                    + "the route ledger alone is not proof. DNS blocks count "
                    + "only requests reaching the local relay.", 12, MUTED);
        }
        RootMultiKernelSession.RootTrafficSnapshot dns = lastSnapshot;
        LinearLayout totals = card(content);
        text(totals, "DNS & AD-BLOCK ACTIVITY", 16, PINK);
        if (dns != null && dns.dnsVerified && dns.dnsCounters != null) {
            text(totals, "Received: " + dns.dnsCounters.received
                    + "  ·  Forwarded: " + dns.dnsCounters.forwarded, 14, WHITE);
            text(totals, "Blocked: " + blockedCount()
                    + "  ·  Failed: " + dns.dnsCounters.failed, 14, LAVENDER);
        } else {
            text(totals, "DNS relay counters unavailable or unverified.", 14, MUTED);
        }
        if (dns != null && dns.dnsVerified && dns.dnsCounters != null
                && dns.trackerEnabled && dns.dnsCounters.received > 0) {
            double percent = 100.0 * dns.dnsCounters.blocked
                    / dns.dnsCounters.received;
            text(totals, String.format(java.util.Locale.ROOT,
                    "Blocked %.1f%% of requests observed by this relay", percent),
                    13, LAVENDER);
        }
        text(totals, relayCounterEvent, 12, LAVENDER);
        text(totals, "Only requests reaching this relay are counted. Browser or "
                + "app-owned encrypted DNS may bypass local filtering.", 12, MUTED);
        LinearLayout continuity = card(content);
        text(continuity, "DNS BASELINE · READ-ONLY COMPARISON", 15, PINK);
        text(continuity, dnsBaselineComparison(), 13, WHITE);
        text(continuity, "The saved baseline compares a verified relay process "
                + "and aggregate counters. It is not continuous monitoring "
                + "or proof of leak prevention.", 12, MUTED);
        showDnsCoverage();
    }

    private void activityTab() {
        LinearLayout group = card(content);
        text(group, "LOCAL ACTIVITY", 16, PINK);
        RootMultiKernelSession.RootTrafficSnapshot snapshot = lastSnapshot;
        if (snapshot == null || !snapshot.rootsAvailable) {
            text(group, "Live root counters unavailable or being inspected.", 13, MUTED);
        } else if (snapshot.countersAvailable) {
            text(group, "Received: " + TunnelTrafficRates.formatTotal(snapshot.received),
                    14, WHITE);
            text(group, "Sent: " + TunnelTrafficRates.formatTotal(snapshot.sent),
                    14, WHITE);
        } else {
            text(group, "Tunnel byte counters unavailable or identities unverified.",
                    13, MUTED);
        }
        text(group, "DNS blocked replies: " + blockedCount()
                + " (current verified relay only)", 14, WHITE);
        text(group, "DNS relay continuity: " + dnsBaselineComparison(), 12, MUTED);
        text(group, "Baseline is an opt-in local comparison, not a guarantee "
                + "of uninterrupted DNS or network protection.", 12, MUTED);
        text(group, "Live tunnel rates: " + throughputLine(), 13, WHITE);
        showNotificationControl(group);
        button(group, "Read current tunnel and firewall diagnostics",
                () -> startActivity(new Intent(this, RootMultiKernelActivity.class)));
    }

    private RootDnsContinuityBaseline.Reading currentDnsReading() {
        RootMultiKernelSession.RootTrafficSnapshot s = lastSnapshot;
        if (s == null) return null;
        RootDnsCounters counters = s.dnsCounters;
        return new RootDnsContinuityBaseline.Reading(
                System.currentTimeMillis(), SystemClock.elapsedRealtime(),
                s.rootsAvailable, s.dnsVerified, s.trackerEnabled,
                s.verifiedTunnels, s.presentTunnels,
                counters == null ? 0 : counters.pid,
                counters == null ? -1 : counters.received,
                counters == null ? -1 : counters.blocked,
                counters == null ? -1 : counters.forwarded,
                counters == null ? -1 : counters.failed);
    }

    private SharedPreferences dnsBaselinePreferences() {
        return getSharedPreferences(DNS_CHECKPOINT_PREFS, MODE_PRIVATE);
    }

    private String dnsBaselineComparison() {
        String encoded = dnsBaselinePreferences().getString(DNS_CHECKPOINT_KEY, null);
        if (encoded == null) {
            return "No baseline saved — record a verified session to compare overnight.";
        }
        try {
            RootDnsContinuityBaseline.Reading previous =
                    RootDnsContinuityBaseline.decode(encoded);
            return RootDnsContinuityBaseline.compare(previous, currentDnsReading());
        } catch (IllegalArgumentException invalid) {
            return "Saved baseline unreadable. Clear it and capture a new verified baseline.";
        }
    }

    private void captureDnsBaseline() {
        RootDnsContinuityBaseline.Reading sample = currentDnsReading();
        try {
            String encoded = RootDnsContinuityBaseline.encode(sample);
            if (!dnsBaselinePreferences().edit().putString(DNS_CHECKPOINT_KEY, encoded).commit()) {
                throw new IllegalStateException("Could not persist this baseline.");
            }
            render();
            new AlertDialog.Builder(this).setTitle("DNS baseline saved")
                    .setMessage("Only aggregate DNS counters, relay PID, tunnel counts "
                            + "and timestamps were saved locally. Open this tab before "
                            + "refreshing the tunnels next time. No DNS history or "
                            + "addresses were recorded.")
                    .setPositiveButton("OK", null).show();
        } catch (IllegalArgumentException | IllegalStateException unavailable) {
            new AlertDialog.Builder(this).setTitle("Baseline unavailable")
                    .setMessage("Verify the root tunnel identities and DNS relay, "
                            + "enable tracker filtering, then wait for aggregate counters. "
                            + "No baseline was stored.")
                    .setPositiveButton("OK", null).show();
        }
    }

    private void showDnsCoverage() {
        LinearLayout group = card(content);
        text(group, "DNS COVERAGE & OVERNIGHT CHECK", 16, PINK);
        text(group, "Local relay: " + dnsState(), 13, WHITE);
        text(group, "Tracker filter: " + blockState(), 13, WHITE);
        text(group, "DNS-port rules: live enforcement must be checked in "
                + "Advanced Controls. This overview does not audit kernel rules.", 12, MUTED);
        text(group, "Upstream encryption and device-wide DNS coverage: "
                + "NOT INDEPENDENTLY VERIFIED. Browser DoH/DoQ may bypass local blocking.",
                12, LAVENDER);
        button(group, "Review DNS & leak verification checklist · read only",
                this::showLeakChecklist);
        text(group, "The comparison is displayed above. Save a baseline only "
                + "when the relay and tunnel identities are verified.", 12, MUTED);
        button(group, "Save verified DNS baseline for overnight comparison",
                this::captureDnsBaseline);
        button(group, "Clear saved DNS baseline", () -> {
            dnsBaselinePreferences().edit().remove(DNS_CHECKPOINT_KEY).apply();
            render();
        });
        button(group, "How to check browser DNS bypass", () ->
                new AlertDialog.Builder(this)
                        .setTitle("Browser DNS bypass — manual check")
                        .setMessage("In Brave, review Settings → Brave Shields & privacy "
                                + "→ Use secure DNS. Disabling browser-specific Secure DNS "
                                + "lets its ordinary DNS requests use the system/Wonhee "
                                + "path. Keep your device's known working Android Private "
                                + "DNS configuration unchanged. Re-test in a fresh tab, "
                                + "then compare against direct queries to 127.0.0.1:53535. "
                                + "This check never changes a setting automatically. "
                                + "Use PCAPdroid root capture on the physical interface "
                                + "for independent network evidence; leave MITM and "
                                + "full payload recording off.")
                        .setPositiveButton("OK", null).show());
        text(group, "Baseline comparison is local and aggregate-only; it cannot "
                + "certify uninterrupted uptime, packet-leak freedom or kill-switch "
                + "coverage. The all-traffic guard stays safety-paused.", 12, MUTED);
    }

    private void showLeakChecklist() {
        new AlertDialog.Builder(this)
                .setTitle("Wonhee verification checklist")
                .setMessage("1. Run Advanced → Audit live DNS firewall + relay: "
                        + "confirm OWNED, MATCH, ALIVE and LISTENING.\n\n"
                        + "2. Query a permitted domain and a blocked test domain "
                        + "through 127.0.0.1:53535, then test browser DNS separately.\n\n"
                        + "3. Compare the expected AirVPN IPv4, IPv6 and WebRTC exit "
                        + "on Wi-Fi and cellular. Repeat DNS leak tests with the "
                        + "configured resolver; geographically diverse Cloudflare "
                        + "addresses alone are not proof of a leak.\n\n"
                        + "4. If browser Secure DNS is enabled, test it separately "
                        + "because it may bypass Wonhee. Leave Android Private DNS "
                        + "at your known working OFF setting.\n\n"
                        + "5. Physical-interface capture is required for independent "
                        + "underlay DNS/IPv6 evidence. No single website or routing "
                        + "simulation proves device-wide leak freedom. The "
                        + "all-traffic kill switch remains paused.")
                .setPositiveButton("Close", null)
                .show();
    }

    private String dnsFirewallLedgerState() {
        // Ledger presence alone cannot attest to the live IPv4/IPv6 rule set.
        return "OFF".equals(session.dnsLedgerStatus())
                ? "No DNS policy recorded — run live audit to verify"
                : "DNS policy recorded — live rule audit required";
    }

    private String killSwitchState() {
        // Never call a guard disabled merely because its ledger is empty.
        if (!"OFF".equals(session.guardLedgerStatus())) {
            return "Guard ownership recorded — live audit and recovery check required";
        }
        return RootGuardSafetyGate.activationPaused()
                ? "Unavailable — activation paused for safety; audit live chains"
                : "Not enabled in ledger — audit live chains before relying on it";
    }

    private String dnsState() {
        RootMultiKernelSession.RootTrafficSnapshot s = lastSnapshot;
        if (s == null) return "Checking…";
        return s.dnsVerified ? "Relay verified · not a leak audit"
                : "Not verified (off, stopped or unavailable)";
    }

    private String blockedCount() {
        RootMultiKernelSession.RootTrafficSnapshot s = lastSnapshot;
        if (s == null || !s.dnsVerified) return "Unavailable";
        if (!s.trackerEnabled) return "Blocking off";
        return s.blocked == null ? "Unavailable" : Long.toString(s.blocked);
    }

    private String blockState() {
        RootMultiKernelSession.RootTrafficSnapshot s = lastSnapshot;
        if (s == null || !s.dnsVerified) return "Not verified";
        if (!s.trackerEnabled) return "Off";
        return blockedCount() + " blocked DNS replies (relay lifetime)";
    }

    private void showProfile(LinearLayout parent, SecureTunnelProfileStore.Profile profile) {
        LinearLayout line = new LinearLayout(this);
        line.setOrientation(LinearLayout.VERTICAL);
        line.setPadding(dp(12), dp(7), dp(12), dp(7));
        line.setBackground(tint(SURFACE_ALT, 12));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
        lp.bottomMargin = dp(7);
        parent.addView(line, lp);
        text(line, profile.name, 15, WHITE);
        String role = profile.role == SecureTunnelProfileStore.Profile.ROLE_INTERNET
                ? "Internet exit" : profile.role == SecureTunnelProfileStore.Profile.ROLE_HOME
                ? "Private destination" : "Custom connection";
        text(line, role + " · individual live status in Advanced Tools", 11, MUTED);
    }

    private void protectionRow(LinearLayout parent, String title, String status) {
        text(parent, title, 14, WHITE);
        text(parent, status, 12, MUTED);
    }

    private LinearLayout card(LinearLayout parent) {
        LinearLayout section = new LinearLayout(this);
        section.setOrientation(LinearLayout.VERTICAL);
        section.setPadding(dp(15), dp(14), dp(15), dp(14));
        section.setBackground(tint(SURFACE, 18));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
        lp.bottomMargin = dp(13);
        parent.addView(section, lp);
        return section;
    }

    private TextView text(LinearLayout parent, String value, int sp, int color) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(sp);
        view.setTextColor(color);
        view.setPadding(0, dp(3), 0, dp(5));
        parent.addView(view);
        return view;
    }

    private void button(LinearLayout parent, String label, Runnable click) {
        Button view = new Button(this);
        view.setAllCaps(false);
        view.setText(label);
        view.setTextSize(14);
        view.setTextColor(BACKGROUND);
        view.setBackground(tint(PINK, 14));
        view.setMinHeight(dp(50));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
        lp.topMargin = dp(8);
        parent.addView(view, lp);
        view.setOnClickListener(v -> click.run());
    }

    private GradientDrawable tint(int color, int corner) {
        GradientDrawable background = new GradientDrawable();
        background.setColor(color);
        background.setCornerRadius(dp(corner));
        return background;
    }

    private int dp(int amount) {
        return Math.round(amount * getResources().getDisplayMetrics().density);
    }
}
