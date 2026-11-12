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
    private int lastRenderedTab = -1;
    private boolean rootMode;
    private ScrollView dashboardScroll;
    private static final String UI_PREFS = "wonhee_everyday_ui_v1";
    private static final String ROOT_MODE_KEY = "root_mode";
    private static final String ROOT_STATE_WARNING_KEY = "root_state_unverified";
    private static final String TAB_KEY = "selected_tab";

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        SharedPreferences ui = getSharedPreferences(UI_PREFS, MODE_PRIVATE);
        // Respect existing root-lab installations; new installs begin with
        // the simpler standard VPN experience. This changes UI only.
        boolean legacyRootUi = !getSharedPreferences("wonhee_root_lab_ui_v1",
                MODE_PRIVATE).getAll().isEmpty()
                || !getSharedPreferences("wonhee_owned_split_routes",
                        MODE_PRIVATE).getAll().isEmpty()
                || !getSharedPreferences("wonhee_owned_dns_policy",
                        MODE_PRIVATE).getAll().isEmpty()
                || !getSharedPreferences("wonhee_owned_guard_policy",
                        MODE_PRIVATE).getAll().isEmpty()
                || getSharedPreferences(ROOT_NOTIFICATION_PREFS, MODE_PRIVATE)
                        .getBoolean("enabled", false);
        rootMode = ui.getBoolean(ROOT_MODE_KEY, legacyRootUi);
        tab = Math.max(0, Math.min(4, ui.getInt(TAB_KEY, 0)));
        if (rootMode) session = RootMultiKernelSession.get(this);
        getWindow().setStatusBarColor(BACKGROUND);
        getWindow().setNavigationBarColor(BACKGROUND);

        LinearLayout frame = new LinearLayout(this);
        frame.setOrientation(LinearLayout.VERTICAL);
        frame.setBackgroundColor(BACKGROUND);
        dashboardScroll = new ScrollView(this);
        dashboardScroll.setFillViewport(true);
        dashboardScroll.setBackgroundColor(BACKGROUND);
        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setPadding(dp(18), dp(18), dp(18), dp(24));
        dashboardScroll.addView(page);
        frame.addView(dashboardScroll, new LinearLayout.LayoutParams(-1, 0, 1f));

        TextView name = text(page, "✦ WONHEE", 26, PINK);
        name.setContentDescription("Wonhee Proxy");
        text(page, "Your network, under your control.", 13, MUTED);

        content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        page.addView(content, new LinearLayout.LayoutParams(-1, -2));

        // Persistent bottom navigation never scrolls offscreen.
        navigation = new LinearLayout(this);
        navigation.setOrientation(LinearLayout.HORIZONTAL);
        navigation.setPadding(dp(7), dp(8), dp(7), dp(9));
        navigation.setBackground(tint(SURFACE, 0));
        frame.addView(navigation, new LinearLayout.LayoutParams(-1, -2));
        setContentView(frame);
        render();

    }

    @Override protected void onResume() {
        super.onResume();
        visible = true;
        traffic.reset();
        liveRates = null;
        lastSnapshot = null; // Never show an old protection snapshot after backgrounding.
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
        if (!rootMode) {
            lastSnapshot = null;
            render();
            handler.postDelayed(refresh, REFRESH_MS);
            return;
        }
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
        if (content == null || navigation == null) return;
        final int scrollY = lastRenderedTab == tab && dashboardScroll != null
                ? dashboardScroll.getScrollY() : 0;
        lastRenderedTab = tab;
        navigation.removeAllViews();
        String[] tabs = {"Home", "Tunnels", "Protect", "Activity", "Settings"};
        for (int i = 0; i < tabs.length; i++) {
            final int next = i;
            Button button = new Button(this);
            button.setAllCaps(false);
            button.setText(tabs[i]);
            button.setContentDescription(tabs[i] + (i == tab ? ", selected" : ""));
            button.setTextSize(11);
            button.setTextColor(i == tab ? BACKGROUND : WHITE);
            button.setBackground(tint(i == tab ? PINK : SURFACE_ALT, 12));
            button.setMinHeight(dp(48));
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, dp(52), 1f);
            lp.setMargins(dp(2), 0, dp(2), 0);
            navigation.addView(button, lp);
            button.setOnClickListener(v -> {
                tab = next;
                getSharedPreferences(UI_PREFS, MODE_PRIVATE).edit()
                        .putInt(TAB_KEY, next).apply();
                render();
            });
        }

        content.removeAllViews();
        text(content, rootMode ? "ADVANCED · ROOT WORKSPACE"
                : "STANDARD · PRIVACY FIRST", 12, LAVENDER);
        if (rootMode) {
            switch (tab) {
                case 0: home(); break;
                case 1: profileTab(); break;
                case 2: protectionTab(); break;
                case 3: activityTab(); break;
                default: settingsTab(); break;
            }
        } else {
            switch (tab) {
                case 0: standardHome(); break;
                case 1: standardProfiles(); break;
                case 2: standardProtection(); break;
                case 3: standardActivity(); break;
                default: settingsTab(); break;
            }
        }
        if (dashboardScroll != null) {
            dashboardScroll.post(() -> dashboardScroll.scrollTo(0, scrollY));
        }
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
        text(group, "LIVE ACTIVITY", 15, PINK);
        text(group, throughputLine(), 20, WHITE);
        text(group, "Speeds from verified VPN tunnels only; not all phone traffic.",
                12, MUTED);
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
        text(group, "Block count resets when the verified DNS relay restarts.",
                12, MUTED);
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
        text(hero, "YOUR CONNECTION", 12, LAVENDER);
        RootMultiKernelSession.RootTrafficSnapshot snapshot = lastSnapshot;
        String status = "Checking your connections…";
        if (snapshot != null && !snapshot.rootsAvailable) {
            status = "Connection status unavailable";
        } else if (snapshot != null && snapshot.presentTunnels == 0) {
            status = "No rooted tunnels running";
        } else if (snapshot != null && snapshot.verifiedTunnels == snapshot.presentTunnels) {
            status = snapshot.verifiedTunnels + " tunnel"
                    + (snapshot.verifiedTunnels == 1 ? "" : "s") + " running";
        } else if (snapshot != null) {
            status = "Connections need attention";
        }
        text(hero, status, 20, WHITE);
        if (snapshot != null && snapshot.rootsAvailable) {
            text(hero, "Identity-verified " + snapshot.verifiedTunnels + "/"
                    + snapshot.presentTunnels + " detected tunnel(s) · "
                    + (snapshot.countersAvailable ? "live counters available"
                            : "live counters not verified"), 13, LAVENDER);
        }
        text(hero, "Tunnel connection is not proof of full-device leak protection.", 12, MUTED);
        button(hero, "Manage connection & safe stop", () -> openRootTab(0));

        showLiveSignals();

        LinearLayout stack = card(content);
        text(stack, "SAVED CONNECTIONS", 15, PINK);
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
                        + " more — see Tunnels", 12, LAVENDER);
            }
        }

        LinearLayout protection = card(content);
        text(protection, "PRIVACY AT A GLANCE", 15, PINK);
        protectionRow(protection, "DNS", dnsState());
        protectionRow(protection, "Ads & trackers", blockState());
        protectionRow(protection, "Kill switch", killSwitchState());
        button(protection, "See all protection details", () -> selectTab(2));

        showRecoveryGuidance();

        // One safe destination appears in Connection Recovery Guidance above.
    }

    /** Friendly guidance is read-only and never changes routing or recovery state. */
    private void showRecoveryGuidance() {
        RootMultiKernelSession.RootTrafficSnapshot s = lastSnapshot;
        LinearLayout group = card(content);
        String title;
        String message;
        if (s == null) {
            title = "CHECKING HEALTH";
            message = "Wonhee is reading your current connection state.";
        } else if (!s.rootsAvailable) {
            title = "STATUS UNAVAILABLE";
            message = "Wonhee cannot inspect the rooted connections. "
                    + "Avoid force-stopping tunnels until you can audit their state.";
        } else if (s.presentTunnels > 0 && s.verifiedTunnels != s.presentTunnels) {
            title = "CONNECTIONS NEED ATTENTION";
            message = "One or more tunnel identities could not be verified. "
                    + "Review connection controls before making changes.";
        } else if (s.presentTunnels == 0) {
            title = "READY FOR A CONNECTION";
            message = "No saved-profile root tunnels were detected. "
                    + "If a previous session was interrupted, check its recovery state first.";
        } else if (!s.countersAvailable) {
            title = "CHECK CONNECTION HEALTH";
            message = "Tunnels were found, but live transfer data is incomplete. "
                    + "Use the read-only diagnostics to investigate.";
        } else if (!s.dnsVerified) {
            title = "DNS NEEDS ATTENTION";
            message = "Tunnels are present but the local DNS relay is not verified. "
                    + "Inspect DNS ownership before restarting anything.";
        } else {
            title = "STATUS AVAILABLE";
            message = "Tunnel identities and the local DNS relay were verified "
                    + "at the last check. This is not a full-device leak test.";
        }
        text(group, title, 15, PINK);
        text(group, message, 13, WHITE);
        button(group, "Connection help & safe controls", () -> openRootTab(0));
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
        button(group, "Manage tunnel connections & routes", () -> openRootTab(1));
        button(group, "Import / edit saved VPN profiles",
                () -> openVpnManager());
        text(group, "Current backend: one default exit plus compatible "
                + "destination-specific profiles. Overlapping routes are refused.", 12, MUTED);
    }

    private void protectionTab() {
        LinearLayout group = card(content);
        text(group, "DNS PROTECTION", 16, PINK);
        protectionRow(group, "Local DNS relay", dnsState());
        protectionRow(group, "Ad & tracker filtering", blockState());
        protectionRow(group, "DNS-port firewall", dnsFirewallLedgerState());
        button(group, "DNS & filtering controls", () -> openRootTab(2));
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
        button(group, "Open network diagnostics", () -> openRootTab(3));
    }


    private void openVpnManager() {
        startActivity(new Intent(this, VpnActivity.class));
    }

    private void openRootTab(int section) {
        Intent intent = new Intent(this, RootMultiKernelActivity.class);
        intent.putExtra("wonhee.lab.tab", Math.max(0, Math.min(3, section)));
        startActivity(intent);
    }

    private Boolean standardVpnConnected() {
        try {
            return WireGuardSession.get(this).isConnected();
        } catch (Exception | LinkageError unavailable) {
            return null;
        }
    }

    private void standardHome() {
        if (getSharedPreferences(UI_PREFS, MODE_PRIVATE)
                .getBoolean(ROOT_STATE_WARNING_KEY, false)) {
            LinearLayout warning = card(content);
            text(warning, "ROOT STATE NOT VERIFIED", 16, PINK);
            text(warning, "An earlier rooted workspace has not been confirmed "
                    + "cleanly stopped. Android VPN status below does not describe "
                    + "kernel VPN tunnels, routing or DNS rules. Do not assume that "
                    + "all rooted networking is off.", 13, WHITE);
            button(warning, "Check rooted network", this::requestRootWorkspace);
        }
        Boolean connected = standardVpnConnected();
        LinearLayout hero = card(content);
        text(hero, "YOUR VPN", 12, LAVENDER);
        text(hero, connected == null ? "Android VPN status unknown"
                : connected ? "Android VPN interface active"
                        : "Android VPN disconnected", 21, WHITE);
        text(hero, connected == null
                ? "Could not read the Android VPN engine. Open connection controls."
                : connected ? "A tunnel interface is active. Encryption, DNS and "
                        + "absence of leaks have not been independently verified."
                        : "Connect a saved VPN profile when you're ready.", 13, MUTED);
        button(hero, connected != null && connected
                ? "Connection details & disconnect" : "Choose VPN & connect",
                this::openVpnManager);

        LinearLayout safety = card(content);
        text(safety, "PRIVACY FIRST", 15, PINK);
        text(safety, "One Android VPN connection at a time. "
                + "The active profile determines which traffic is included; "
                + "split routes may leave other traffic outside the VPN.", 14, WHITE);
        text(safety, "For protection during disconnections, enable Android's "
                + "Always-on VPN and Block connections without VPN in system settings. "
                + "Verify this before relying on fail-closed protection.", 12, MUTED);
        button(safety, "Open Android VPN settings", this::openSystemVpnSettings);

        LinearLayout shortcuts = card(content);
        text(shortcuts, "QUICK ACCESS", 15, PINK);
        button(shortcuts, "Manage saved connections", () -> selectTab(1));
        button(shortcuts, "Protection & privacy guidance", () -> selectTab(2));
    }

    private void standardProfiles() {
        LinearLayout group = card(content);
        text(group, "YOUR CONNECTIONS", 18, PINK);
        if (profileStoreError) {
            text(group, "Encrypted profile storage is unavailable.", 13, MUTED);
        } else if (profiles.isEmpty()) {
            text(group, "No saved VPN profiles yet. Import a WireGuard profile to start.",
                    14, MUTED);
        } else {
            text(group, profiles.size() + " saved profile(s) · select one in VPN settings",
                    13, MUTED);
            for (SecureTunnelProfileStore.Profile profile : profiles) {
                text(group, "• " + profile.name, 15, WHITE);
            }
        }
        button(group, "Import / edit / connect", this::openVpnManager);
        text(group, "Standard mode manages one Android VPN tunnel at a time. "
                + "It does not offer root-only per-app or multi-exit routing.",
                12, MUTED);
    }

    private void standardProtection() {
        LinearLayout group = card(content);
        text(group, "PROTECTION", 18, PINK);
        text(group, "Privacy-first connection controls", 15, WHITE);
        Boolean active = standardVpnConnected();
        protectionRow(group, "VPN interface", active == null
                ? "Unknown" : active ? "Active · traffic protection not audited"
                        : "Disconnected");
        protectionRow(group, "Disconnect protection",
                "Use Android's Always-on and Block connections without VPN settings");
        protectionRow(group, "DNS / ad blocking",
                "Depends on your active VPN configuration · not verified here");
        protectionRow(group, "Wonhee all-traffic kill switch",
                "Not yet released or verified");
        button(group, "Android VPN & lockdown settings", this::openSystemVpnSettings);
        text(group, "Wonhee does not claim that an active VPN interface alone "
                + "guarantees leak-free traffic.", 12, MUTED);
    }

    private void standardActivity() {
        LinearLayout group = card(content);
        text(group, "ACTIVITY", 18, PINK);
        text(group, "Standard VPN throughput, peer handshakes and read-only "
                + "diagnostics are available in the connection manager.", 14, WHITE);
        text(group, "Root-only blocked DNS counters and kernel interface stats "
                + "are intentionally not shown in Standard mode.", 12, MUTED);
        button(group, "See VPN statistics", this::openVpnManager);
    }

    private void openSystemVpnSettings() {
        try {
            startActivity(new Intent(android.provider.Settings.ACTION_VPN_SETTINGS));
        } catch (RuntimeException unavailable) {
            new AlertDialog.Builder(this).setTitle("Settings unavailable")
                    .setMessage("Open Android Settings, then search for VPN. "
                            + "Enable Always-on and Block connections without VPN "
                            + "if supported by your device and profile.")
                    .setPositiveButton("OK", null).show();
        }
    }

    private void selectTab(int selected) {
        tab = Math.max(0, Math.min(4, selected));
        getSharedPreferences(UI_PREFS, MODE_PRIVATE).edit()
                .putInt(TAB_KEY, tab).apply();
        render();
    }

    private void setRootMode(boolean enabled) {
        rootMode = enabled;
        if (enabled) session = RootMultiKernelSession.get(this);
        lastSnapshot = null;
        liveRates = null;
        traffic.reset();
        tab = 0;
        lastRenderedTab = -1;
        SharedPreferences.Editor choice =
                getSharedPreferences(UI_PREFS, MODE_PRIVATE).edit()
                        .putBoolean(ROOT_MODE_KEY, enabled).putInt(TAB_KEY, 0);
        if (enabled) choice.putBoolean(ROOT_STATE_WARNING_KEY, false);
        choice.apply();
        handler.removeCallbacks(refresh);
        loadSavedProfiles();
        refreshSnapshot();
    }

    private void requestRootWorkspace() {
        new AlertDialog.Builder(this)
                .setTitle("Enable advanced root workspace?")
                .setMessage("This shows multi-tunnel, split-routing and diagnostic "
                        + "controls. It does not connect or modify your network. "
                        + "Root access is requested only for the status check and "
                        + "the existing explicit root operations.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Check root", (dialog, which) ->
                        RootMultiKernelSession.get(this).readRootTrafficSnapshot(snapshot -> {
                            if (isFinishing() || isDestroyed()) return;
                            if (snapshot != null && snapshot.rootsAvailable) {
                                setRootMode(true);
                            } else {
                                new AlertDialog.Builder(this)
                                        .setTitle("Root access unavailable")
                                        .setMessage("The advanced workspace needs "
                                                + "working root access. No tunnel "
                                                + "or firewall settings were changed.")
                                        .setPositiveButton("OK", null).show();
                            }
                        }))
                .show();
    }

    private void settingsTab() {
        LinearLayout group = card(content);
        text(group, "PREFERENCES", 18, PINK);
        text(group, "Display mode: " + (rootMode ? "Root advanced" : "Standard privacy first"),
                14, WHITE);
        if (rootMode) {
            text(group, "Switching views never disconnects root tunnels. "
                    + "Use Safe Stop and verify clean state before changing mode.",
                    12, MUTED);
            button(group, "Switch to Standard interface", () -> {
                boolean clean = lastSnapshot != null && lastSnapshot.rootsAvailable
                        && lastSnapshot.presentTunnels == 0
                        && "OFF".equals(session.dnsLedgerStatus())
                        && "OFF".equals(session.guardLedgerStatus());
                if (!clean) {
                    new AlertDialog.Builder(this)
                            .setTitle("Root network may still be active")
                            .setMessage("Wonhee cannot verify a clean root stop. "
                                    + "Standard mode shows only the Android VPN, "
                                    + "not existing kernel tunnels, DNS or routing rules. "
                                    + "Use Safe Controls first when possible. "
                                    + "Switching anyway will keep a clear warning "
                                    + "on Standard Home; it changes no network settings.")
                            .setNeutralButton("Safe Controls", (d, w) -> openRootTab(0))
                            .setNegativeButton("Stay in Root mode", null)
                            .setPositiveButton("Switch with warning", (d, w) -> {
                                getSharedPreferences(UI_PREFS, MODE_PRIVATE).edit()
                                        .putBoolean(ROOT_STATE_WARNING_KEY, true).apply();
                                setRootMode(false);
                            }).show();
                    return;
                }
                new AlertDialog.Builder(this).setTitle("Change to Standard view?")
                        .setMessage("The saved root profiles remain available. "
                                + "This switches only the interface.")
                        .setNegativeButton("Cancel", null)
                        .setPositiveButton("Switch view", (d, w) -> {
                            getSharedPreferences(UI_PREFS, MODE_PRIVATE).edit()
                                    .putBoolean(ROOT_STATE_WARNING_KEY, false).apply();
                            setRootMode(false);
                        }).show();
            });
            showNotificationControl(group);
        } else {
            text(group, "Advanced rooted networking is optional and requires "
                    + "an explicit root permission check.", 12, MUTED);
            button(group, "Unlock rooted multi-tunnel workspace", this::requestRootWorkspace);
            button(group, "VPN notifications & preferences", this::openVpnManager);
        }
        LinearLayout tools = card(content);
        text(tools, "TOOLS", 16, PINK);
        button(tools, "WireGuard profile manager", this::openVpnManager);
        button(tools, "Ultgram proxy companion",
                () -> startActivity(new Intent(this, MainActivity.class)));
        if (rootMode) {
            button(tools, "Advanced diagnostics", () -> openRootTab(3));
        }
        text(tools, "Your display choice is saved on this device. "
                + "It never changes firewall rules or tunnel connections.", 12, MUTED);
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
