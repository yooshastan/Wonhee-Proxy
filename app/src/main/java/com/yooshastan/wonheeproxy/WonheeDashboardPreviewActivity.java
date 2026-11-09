package com.yooshastan.wonheeproxy;

import android.app.Activity;
import android.content.Intent;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
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

    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Runnable refresh = this::refreshSnapshot;
    private final List<SecureTunnelProfileStore.Profile> profiles = new ArrayList<>();
    private RootMultiKernelSession session;
    private RootMultiKernelSession.RootTrafficSnapshot lastSnapshot;
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
        text(page, "Candy Pink  •  Multi-connection dashboard preview", 12, MUTED);
        text(page, "Read-only preview: use existing controls for all connection changes.",
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
        loadSavedProfiles();
        refreshSnapshot();
    }

    @Override protected void onPause() {
        visible = false;
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
            render();
            handler.postDelayed(refresh, REFRESH_MS);
        });
    }

    private void render() {
        if (content == null) return;
        navigation.removeAllViews();
        String[] tabs = {"Home", "Profiles", "Protection", "Activity"};
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
        button(content, "Advanced connection controls / Safe stop",
                () -> startActivity(new Intent(this, RootMultiKernelActivity.class)));
        text(content, "All-traffic kill switch activation is paused for safety. DNS-port "
                + "filtering is separate. This preview does not verify live firewall "
                + "rules or change tunnels, routes, DNS, or firewall settings.", 12, MUTED);
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
        text(hero, "Tunnel connection is not proof of full-device leak protection.", 12, MUTED);

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
        protectionRow(protection, "Encrypted DNS", dnsState());
        protectionRow(protection, "Ads & Trackers", blockState());
        protectionRow(protection, "DNS-port firewall", dnsFirewallLedgerState());
        protectionRow(protection, "All-traffic kill switch", killSwitchState());

        LinearLayout actions = card(content);
        button(actions, "Open existing Connect / Safe Disconnect controls",
                () -> startActivity(new Intent(this, RootMultiKernelActivity.class)));
        text(actions, "For this first preview, the proven advanced manager handles "
                + "all network changes and recovery.", 12, MUTED);
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
        } else {
            for (SecureTunnelProfileStore.Profile profile : profiles) showProfile(group, profile);
        }
        button(group, "Import / edit saved VPN profiles",
                () -> startActivity(new Intent(this, VpnActivity.class)));
        text(group, "Current backend: one default exit plus compatible "
                + "destination-specific profiles. Overlapping routes are refused.", 12, MUTED);
    }

    private void protectionTab() {
        LinearLayout group = card(content);
        text(group, "YOUR PROTECTION FORMULA", 16, PINK);
        protectionRow(group, "1  Connections",
                lastSnapshot == null ? "Checking…" : lastSnapshot.rootsAvailable
                    ? lastSnapshot.verifiedTunnels + " verified selected-profile tunnels"
                    : "Unavailable");
        protectionRow(group, "2  Routing", "Details and audits in Advanced Tools");
        protectionRow(group, "3  Encrypted DNS", dnsState());
        protectionRow(group, "4  Ad & Tracker Blocking", blockState());
        protectionRow(group, "5  DNS-port firewall", dnsFirewallLedgerState());
        protectionRow(group, "6  All-traffic kill switch", killSwitchState());
        text(group, "The DNS firewall protects selected DNS ports only. The all-traffic "
                + "kill switch is a separate, safety-paused experiment after a "
                + "connectivity interruption. Ledger status is not proof of live rules; "
                + "use Advanced Tools to audit IPv4 and IPv6 chains.", 12, MUTED);
        text(group, "Blocked count measures DNS replies blocked by Wonhee's verified "
                + "active relay since that relay started. It is not a count of page ads, "
                + "all trackers, or device-wide traffic.", 12, MUTED);
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
        text(group, "DNS blocked replies: " + blockedCount(), 14, WHITE);
        text(group, "Live ↓/↑ rates are available through the optional notification "
                + "in the advanced connection controls.", 12, MUTED);
        button(group, "Read current tunnel and firewall diagnostics",
                () -> startActivity(new Intent(this, RootMultiKernelActivity.class)));
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
