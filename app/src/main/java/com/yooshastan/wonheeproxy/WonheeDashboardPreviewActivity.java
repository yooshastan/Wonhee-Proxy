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
import android.view.WindowInsets;
import android.widget.ImageView;
import android.widget.CheckBox;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.content.res.ColorStateList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
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
    private static final int NAV_BACKGROUND = 0xff22182d;

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
    private static final String QUICK_SELECTION_KEY = "last_quick_profiles";

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
        if (!ui.contains(ROOT_MODE_KEY)) {
            // Keep the legacy manager consistent with the migrated root workspace.
            ui.edit().putBoolean(ROOT_MODE_KEY, rootMode).apply();
        }
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

        content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        page.addView(content, new LinearLayout.LayoutParams(-1, -2));

        // Persistent bottom navigation never scrolls offscreen.
        navigation = new LinearLayout(this);
        navigation.setOrientation(LinearLayout.HORIZONTAL);
        navigation.setPadding(dp(7), dp(8), dp(7), dp(9));
        navigation.setBackground(tint(SURFACE, 0));
        frame.addView(navigation, new LinearLayout.LayoutParams(-1, -2));
        // Android 15/16 enforce edge-to-edge for apps targeting recent SDKs.
        // Reserve system bars explicitly so navigation never sits under gestures
        // and page headings never overlap the clock or camera cutout.
        frame.setOnApplyWindowInsetsListener((v, insets) -> {
            int top, bottom, left, right;
            if (Build.VERSION.SDK_INT >= 30) {
                android.graphics.Insets safe = insets.getInsets(
                        WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
                top = safe.top;
                bottom = safe.bottom;
                left = safe.left;
                right = safe.right;
            } else {
                top = insets.getSystemWindowInsetTop();
                bottom = insets.getSystemWindowInsetBottom();
                left = insets.getSystemWindowInsetLeft();
                right = insets.getSystemWindowInsetRight();
            }
            v.setPadding(left, top, right, bottom);
            return insets;
        });
        setContentView(frame);
        frame.requestApplyInsets();
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
        String[] tabs = {"Home", "Tunnels", "Protect", "Stats", "More"};
        int[] icons = {
                android.R.drawable.ic_menu_view,
                android.R.drawable.ic_menu_add,
                android.R.drawable.ic_lock_lock,
                android.R.drawable.ic_menu_info_details,
                android.R.drawable.ic_menu_preferences
        };
        navigation.setBackgroundColor(NAV_BACKGROUND);
        for (int i = 0; i < tabs.length; i++) {
            final int next = i;
            boolean selected = i == tab;
            LinearLayout item = new LinearLayout(this);
            item.setOrientation(LinearLayout.VERTICAL);
            item.setGravity(android.view.Gravity.CENTER);
            item.setPadding(dp(3), dp(5), dp(3), dp(5));
            item.setMinimumHeight(dp(60));
            item.setBackground(tint(selected ? SURFACE_ALT : NAV_BACKGROUND, 13));
            item.setClickable(true);
            item.setFocusable(true);
            item.setContentDescription(tabs[i] + (selected ? ", selected" : ""));
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, -2, 1f);
            lp.setMargins(dp(2), 0, dp(2), 0);
            navigation.addView(item, lp);

            ImageView image = new ImageView(this);
            image.setImageResource(icons[i]);
            image.setColorFilter(selected ? PINK : MUTED);
            image.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
            item.addView(image, new LinearLayout.LayoutParams(dp(22), dp(22)));

            TextView caption = new TextView(this);
            caption.setText(tabs[i]);
            caption.setTextSize(10);
            caption.setGravity(android.view.Gravity.CENTER);
            caption.setSingleLine(true);
            caption.setEllipsize(android.text.TextUtils.TruncateAt.END);
            caption.setTextColor(selected ? WHITE : MUTED);
            caption.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
            LinearLayout.LayoutParams textLp =
                    new LinearLayout.LayoutParams(-1, -2);
            textLp.topMargin = dp(3);
            item.addView(caption, textLp);
            item.setOnClickListener(v -> selectTab(next));
        }

        content.removeAllViews();
        if (tab != 0) text(content, rootMode ? "ROOT WORKSPACE"
                : "STANDARD VPN", 12, LAVENDER);
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


    /** A persistent, named tunnel selection. Never changes a running route. */
    private Set<String> chosenRootTunnels() {
        SharedPreferences prefs = getSharedPreferences(UI_PREFS, MODE_PRIVATE);
        Set<String> existing = prefs.getStringSet(QUICK_SELECTION_KEY, null);
        if (existing != null) return new LinkedHashSet<>(existing);

        // New user-friendly default: at most one internet exit and one private
        // destination. Additional profiles are opt-in; no routes are activated.
        Set<String> suggested = new LinkedHashSet<>();
        boolean hasInternet = false;
        boolean hasPrivate = false;
        for (SecureTunnelProfileStore.Profile profile : profiles) {
            if (!hasInternet && (profile.role == SecureTunnelProfileStore.Profile.ROLE_INTERNET
                    || profile.routeMode == VpnRouteModes.ALL)) {
                suggested.add(profile.name);
                hasInternet = true;
            } else if (!hasPrivate && (profile.role == SecureTunnelProfileStore.Profile.ROLE_HOME
                    || profile.routeMode == VpnRouteModes.HOME)) {
                suggested.add(profile.name);
                hasPrivate = true;
            }
        }
        if (suggested.isEmpty() && !profiles.isEmpty()) suggested.add(profiles.get(0).name);
        prefs.edit().putStringSet(QUICK_SELECTION_KEY, suggested).apply();
        return suggested;
    }

    private void chooseRootTunnel(String name, boolean choose) {
        Set<String> chosen = chosenRootTunnels();
        if (choose) chosen.add(name);
        else chosen.remove(name);
        getSharedPreferences(UI_PREFS, MODE_PRIVATE).edit()
                .putStringSet(QUICK_SELECTION_KEY, chosen).apply();
        // No network operations. Leave the current scroll and checkbox state alone.
    }

    /** Selection belongs on Home rather than in the advanced connection laboratory. */
    private void showQuickTunnelPicker(LinearLayout parent, boolean includeStatus) {
        if (profileStoreError) {
            text(parent, "Saved tunnels unavailable — check secure storage.", 13, MUTED);
            return;
        }
        if (profiles.isEmpty()) {
            text(parent, "No tunnels yet. Add a WireGuard configuration above.", 13, MUTED);
            return;
        }
        Set<String> selected = chosenRootTunnels();
        for (SecureTunnelProfileStore.Profile profile : profiles) {
            LinearLayout item = new LinearLayout(this);
            item.setOrientation(LinearLayout.VERTICAL);
            item.setPadding(dp(10), dp(4), dp(10), dp(4));
            item.setBackground(tint(SURFACE_ALT, 12));
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
            lp.bottomMargin = dp(6);
            parent.addView(item, lp);
            CheckBox check = new CheckBox(this);
            check.setText(profile.name);
            check.setTextColor(WHITE);
            check.setTextSize(15);
            check.setButtonTintList(ColorStateList.valueOf(PINK));
            check.setMinHeight(dp(48));
            check.setChecked(selected.contains(profile.name));
            check.setOnCheckedChangeListener((view, checked) ->
                    chooseRootTunnel(profile.name, checked));
            item.addView(check);
            if (includeStatus) {
                String purpose = profile.routeMode == VpnRouteModes.ALL
                        ? "Internet exit" : profile.routeMode == VpnRouteModes.HOME
                        ? "Private destinations" : "Custom routes";
                text(item, purpose, 11, MUTED);
            }
        }
    }

    private void home() {
        RootMultiKernelSession.RootTrafficSnapshot snapshot = lastSnapshot;
        boolean known = snapshot != null && snapshot.rootsAvailable;
        boolean running = known && snapshot.presentTunnels > 0;
        boolean cleanIdentity = known && snapshot.presentTunnels == snapshot.verifiedTunnels;

        LinearLayout hero = card(content);
        Button primary = button(hero, running ? (cleanIdentity ? "Stop" : "Review connection")
                : known ? "Start" : "Checking connection…",
                running && cleanIdentity ? () -> launchRootQuickAction("stop")
                        : running ? () -> openRootTab(0)
                        : () -> launchRootQuickAction("start"));
        primary.setTextSize(20);
        primary.setMinHeight(dp(72));
        primary.setEnabled(known);
        secondaryButton(hero, "＋  Add tunnel", this::openTunnelImporter);

        text(hero, "CHOOSE YOUR TUNNELS", 13, LAVENDER);
        showQuickTunnelPicker(hero, false);

        String status = "Checking your connection…";
        if (known && snapshot.presentTunnels == 0) {
            status = "Not connected";
        } else if (running && cleanIdentity) {
            status = snapshot.verifiedTunnels + " tunnel"
                    + (snapshot.verifiedTunnels == 1 ? "" : "s") + " running";
        } else if (running) {
            status = "Connection needs attention";
        } else if (snapshot != null) {
            status = "Connection status unavailable";
        }
        text(hero, status, 17, WHITE);
        if (profileStoreError) {
            text(hero, "Saved connections unavailable", 12, MUTED);
        } else {
            text(hero, profiles.size() + " saved connection"
                    + (profiles.size() == 1 ? "" : "s"), 12, MUTED);
        }

        LinearLayout protection = card(content);
        text(protection, "PROTECTION", 15, PINK);
        protectionRow(protection, "DNS", dnsState());
        protectionRow(protection, "Ads & trackers", blockState());
        protectionRow(protection, "Kill switch", "Not yet enabled");
        secondaryButton(protection, "Protection details", () -> selectTab(2));

        showLiveSignals();
        // Keep troubleshooting off Home unless a real state needs attention.
        if (snapshot != null && (!snapshot.rootsAvailable
                || snapshot.presentTunnels != snapshot.verifiedTunnels
                || (snapshot.presentTunnels > 0 && !snapshot.dnsVerified))) {
            showRecoveryGuidance();
        }
    }

    private void launchRootQuickAction(String action) {
        RootMultiKernelSession.RootTrafficSnapshot snapshot = lastSnapshot;
        if (snapshot == null || !snapshot.rootsAvailable) {
            new AlertDialog.Builder(this).setTitle("Connection status unavailable")
                    .setMessage("Wonhee cannot verify your active tunnels. "
                            + "Inspect the connection before changing it.")
                    .setPositiveButton("Connection controls", (d, w) -> openRootTab(0))
                    .setNegativeButton("Cancel", null).show();
            return;
        }
        ArrayList<String> chosen = new ArrayList<>();
        if ("stop".equals(action)) {
            // Always propose stopping EVERY detected verified tunnel. Do not
            // confuse the next-start selection with current active connections.
            for (RootMultiKernelSession.TunnelStatus tunnel : snapshot.tunnels) {
                if (tunnel.present && tunnel.verified) chosen.add(tunnel.name);
            }
        } else {
            Set<String> selected = chosenRootTunnels();
            for (SecureTunnelProfileStore.Profile profile : profiles) {
                if (selected.contains(profile.name)) chosen.add(profile.name);
            }
            if (chosen.isEmpty()) {
                new AlertDialog.Builder(this).setTitle("Choose a tunnel")
                        .setMessage("Select at least one tunnel on Home, then press Start.")
                        .setPositiveButton("OK", null).show();
                return;
            }
        }
        Intent intent = new Intent(this, RootMultiKernelActivity.class);
        intent.putExtra("wonhee.lab.tab", 0);
        intent.putExtra("wonhee.quick.action", action);
        intent.putStringArrayListExtra("wonhee.quick.profiles", chosen);
        startActivity(intent);
    }

    private void openTunnelImporter() {
        Intent intent = new Intent(this, VpnActivity.class);
        intent.putExtra("wonhee.quick.action", "import");
        startActivity(intent);
    }

    private void secondaryButton(LinearLayout parent, String title, Runnable onClick) {
        Button action = button(parent, title, onClick);
        action.setTextColor(WHITE);
        action.setBackground(tint(SURFACE_ALT, 14));
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
        text(group, "YOUR TUNNELS", 16, PINK);
        button(group, "＋  Add tunnel", this::openTunnelImporter);
        text(group, "Choose which tunnels Start uses on Home.", 12, MUTED);
        showQuickTunnelPicker(group, true);
        button(group, "Manage tunnel connections & routes", () -> openRootTab(1));
        secondaryButton(group, "Edit imported profiles", this::openVpnManager);
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
        String comparison = dnsBaselineComparison();
        text(group, comparison.toUpperCase(java.util.Locale.ROOT)
                        .contains("REBOOT OR DEVICE CLOCK CHANGE SUSPECTED")
                        ? "DNS history needs a fresh check after a possible restart "
                                + "or clock change."
                        : comparison.startsWith("No baseline saved")
                                ? "DNS history has not been saved." : "DNS history is available "
                                        + "in Protection details.", 12, MUTED);
        secondaryButton(group, "DNS history details",
                () -> new AlertDialog.Builder(this)
                        .setTitle("DNS continuity")
                        .setMessage(comparison + "\\n\\nThis is historical monitoring "
                                + "only. A missing comparison is not proof "
                                + "that current DNS or VPN protection failed.")
                        .setPositiveButton("OK", null).show());
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
        Boolean connected = standardVpnConnected();
        LinearLayout hero = card(content);
        Button primary = button(hero, connected == null ? "Checking connection…"
                : connected ? "Stop" : "Start",
                () -> openStandardQuickAction(Boolean.TRUE.equals(connected)
                        ? "stop" : "start"));
        primary.setTextSize(20);
        primary.setMinHeight(dp(72));
        primary.setEnabled(connected != null);
        secondaryButton(hero, "＋  Add tunnel", this::openTunnelImporter);
        text(hero, connected == null ? "Checking your VPN…" :
                connected ? "VPN running" : "Not connected", 17, WHITE);
        text(hero, profileStoreError ? "Saved connections unavailable"
                : profiles.size() + " saved connection"
                        + (profiles.size() == 1 ? "" : "s"), 12, MUTED);

        if (getSharedPreferences(UI_PREFS, MODE_PRIVATE)
                .getBoolean(ROOT_STATE_WARNING_KEY, false)) {
            LinearLayout warning = card(content);
            text(warning, "ROOT STATE NOT VERIFIED", 15, PINK);
            text(warning, "A previous rooted network has not been confirmed "
                    + "cleanly stopped. Android VPN status does not describe "
                    + "kernel tunnels or firewall rules.", 12, WHITE);
            secondaryButton(warning, "Inspect rooted network", this::requestRootWorkspace);
        }
        LinearLayout tunnels = card(content);
        text(tunnels, "YOUR TUNNELS", 15, PINK);
        if (profileStoreError) {
            text(tunnels, "Encrypted profile storage unavailable.", 13, MUTED);
        } else if (profiles.isEmpty()) {
            text(tunnels, "Add a WireGuard configuration to begin.", 13, MUTED);
        } else {
            int shown = Math.min(2, profiles.size());
            for (int i = 0; i < shown; i++) showProfile(tunnels, profiles.get(i));
        }
        secondaryButton(tunnels, "See all tunnels", () -> selectTab(1));

        LinearLayout protection = card(content);
        text(protection, "PRIVACY", 15, PINK);
        protectionRow(protection, "Android VPN", connected == null ? "Status unavailable"
                : connected ? "Interface active · protection unverified" : "Off");
        protectionRow(protection, "Kill switch", "Configure Android VPN lockdown");
        secondaryButton(protection, "Protection settings", () -> selectTab(2));
    }

    private void openStandardQuickAction(String action) {
        Intent intent = new Intent(this, VpnActivity.class);
        intent.putExtra("wonhee.quick.action", action);
        startActivity(intent);
    }

    private void standardProfiles() {
        LinearLayout group = card(content);
        text(group, "YOUR TUNNELS", 18, PINK);
        button(group, "＋  Add tunnel", this::openTunnelImporter);
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
        secondaryButton(group, "Manage existing tunnels", this::openVpnManager);
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
        secondaryButton(tools, "Ultgram proxy tools",
                () -> startActivity(new Intent(this, MainActivity.class)));
        if (rootMode) {
            secondaryButton(tools, "Advanced diagnostics", () -> openRootTab(3));
        }
        text(tools, "Settings change the display only unless you explicitly "
                + "open a connection or network control.", 12, MUTED);
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

    private Button button(LinearLayout parent, String label, Runnable click) {
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
        return view;
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
