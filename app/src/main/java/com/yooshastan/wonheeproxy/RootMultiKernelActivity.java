package com.yooshastan.wonheeproxy;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.view.WindowInsets;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Small opt-in UI for generalizing root tunnel controls without regressing the pair. */
public final class RootMultiKernelActivity extends Activity {
    private static final int BACKGROUND = 0xff12101d;
    private static final int PANEL = 0xff242033;
    private static final int PINK = 0xfffbadd8;
    private static final int WHITE = 0xfff8f1f9;
    private static final int MUTED = 0xffc4b7c9;

    private SecureTunnelProfileStore store;
    private RootMultiKernelSession session;
    private RootSessionJournal journal;
    private final List<SecureTunnelProfileStore.Profile> saved = new ArrayList<>();
    private final Map<String, CheckBox> selection = new LinkedHashMap<>();
    private LinearLayout profileRows;
    private TextView output;
    private Button connect;
    private Button disconnect;
    private Button preview;
    private Button inspect;
    private Button audit;
    private Button apply;
    private Button remove;
    private Button recover;
    private Button guardReadiness;
    private Button dnsAudit;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        store = new SecureTunnelProfileStore(this);
        session = RootMultiKernelSession.get(this);
        journal = new RootSessionJournal(this);
        journal.record("APP", "Experimental multi-tunnel manager opened");

        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(BACKGROUND);
        scroll.setFillViewport(true);
        scroll.setClipToPadding(false);
        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setPadding(dp(18), dp(20), dp(18), dp(80));
        scroll.addView(page);
        scroll.setOnApplyWindowInsetsListener((v, insets) -> {
            int nav = Build.VERSION.SDK_INT >= 30
                    ? insets.getInsets(WindowInsets.Type.navigationBars()).bottom
                    : insets.getSystemWindowInsetBottom();
            page.setPadding(dp(18), dp(20), dp(18), dp(24) + Math.max(dp(56), nav));
            return insets;
        });
        setContentView(scroll);
        scroll.requestApplyInsets();

        label(page, "MULTI-TUNNEL LAB", 25, PINK);
        label(page, "Batch C · network protection readiness (read-only)", 14, WHITE);
        label(page, "EXPERIMENTAL: this is separate from the tested Home + AirVPN pair. "
                + "Stop that pair first. Root changes may interrupt Internet access. "
                + "Keep USB ADB recovery available. No firewall, kill switch, per-app "
                + "routing verification, encrypted DNS or fail-closed protection is "
                + "automatic here. Routing overrides require separate confirmation.", 13, PINK);

        LinearLayout configs = card(page);
        label(configs, "SELECT ACTIVE PROFILES", 18, PINK);
        label(configs, "Select any combination of saved profiles. A default Internet "
                + "route can coexist with distinct split destinations, but overlapping "
                + "split routes or two defaults are refused. Up to eight profiles "
                + "are supported by the current encrypted store.", 13, MUTED);
        profileRows = new LinearLayout(this);
        profileRows.setOrientation(LinearLayout.VERTICAL);
        configs.addView(profileRows);
        Button manage = button(configs, "Import / edit encrypted profiles");
        manage.setOnClickListener(v -> startActivity(new Intent(this, VpnActivity.class)));
        preview = button(configs, "Preview selected routes · read only");
        preview.setOnClickListener(v -> run("Preview routes", false, session::preview));

        LinearLayout controls = card(page);
        label(controls, "CONNECTION CONTROLS", 18, PINK);
        connect = button(controls, "Connect selected tunnels");
        connect.setOnClickListener(v -> confirm(true));
        disconnect = button(controls, "Disconnect selected tunnels");
        disconnect.setOnClickListener(v -> confirm(false));
        label(controls, "Disconnect checks the WireGuard public identities of all "
                + "selected interfaces before changing any, including after an app "
                + "restart. Unknown interfaces are never removed.", 13, MUTED);
        inspect = button(controls, "Read live kernel status");
        inspect.setOnClickListener(v -> run("Read multi-tunnel state", true, session::inspect));

        LinearLayout routing = card(page);
        label(routing, "EXPERIMENTAL ROUTING OVERRIDES", 18, PINK);
        label(routing, "Batch B addresses the observed Home split route choosing the "
                + "AirVPN default. Inspect the read-only audit first. The optional fix "
                + "adds narrowly scoped Wonhee-owned rules ahead of Android's default "
                + "selection, records a persistent rollback ledger, and verifies root "
                + "route lookups. It is NOT a leak test or kill switch.", 13, MUTED);
        audit = button(routing, "Audit effective routes · read only");
        audit.setOnClickListener(v -> run("Audit UID-0 routes", false, session::auditRouting));
        apply = button(routing, "Apply split-route correction · experimental");
        apply.setOnClickListener(v -> new AlertDialog.Builder(this)
                .setTitle("Install owned routing priority rules?")
                .setMessage("Only selected, identity-verified running tunnels can be used. "
                        + "Wonhee will refuse policy-rule collisions and unsafe WireGuard "
                        + "endpoint marks, save a rollback ledger, then check root routes. "
                        + "This changes device routing and may interrupt connectivity. "
                        + "Keep USB ADB recovery ready. No kill switch is installed.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Apply rules", (dialog, which) ->
                        run("Install split route priority", false, session::applyRouting))
                .show());
        recover = button(routing, "Verify + recover matching routing rules");
        recover.setOnClickListener(v -> new AlertDialog.Builder(this)
                .setTitle("Recover exact matching routing rules?")
                .setMessage("Use only if the audit says rollback ledger EMPTY but "
                        + "priority-12500+ rules exist. Wonhee checks the selected "
                        + "encrypted profiles, live WireGuard identities and every "
                        + "reserved kernel rule before restoring the rollback record. "
                        + "No kernel rule or tunnel changes during recovery. "
                        + "Unknown rules are never adopted.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Verify + recover", (dialog, which) ->
                        run("Recover exact matching owned rules", false, session::recoverRouting))
                .show());
        remove = button(routing, "Remove Wonhee routing overrides");
        remove.setOnClickListener(v -> new AlertDialog.Builder(this)
                .setTitle("Remove Wonhee's routing rules?")
                .setMessage("The app will remove ONLY exactly matching rules recorded in "
                        + "its rollback ledger, even after an app restart. Kernel tunnels "
                        + "remain up. Rules belonging to anything else are not touched.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Remove owned rules", (dialog, which) ->
                        run("Remove owned routing rules", true, session::removeRouting))
                .show());

        LinearLayout privacy = card(page);
        label(privacy, "NETWORK PROTECTION · READ ONLY", 18, PINK);
        label(privacy, "Privacy Guard is a readiness report, NOT an active kill switch. "
                + "It inspects all selected kernel tunnel identities, UDP transport "
                + "marks/endpoints, public IPv4/IPv6 and split routes, existing "
                + "firewall capability and rollback ownership. It cannot prove "
                + "app-level DNS or fail-closed behavior.", 13, MUTED);
        guardReadiness = button(privacy, "Check multi-tunnel guard readiness");
        guardReadiness.setOnClickListener(v ->
                run("Audit multi-tunnel guard readiness", false, session::auditProtection));
        dnsAudit = button(privacy, "Audit configured DNS routes");
        dnsAudit.setOnClickListener(v ->
                run("Audit configured DNS routes", false, session::auditResolverRoutes));
        label(privacy, "Kill switch: OFF. No iptables/ip6tables changes, DNS blocking "
                + "or hidden network rules are installed by these checks. "
                + "Keep USB ADB recovery ready for future enforcement testing.", 13, PINK);

        LinearLayout diagnostics = card(page);
        label(diagnostics, "LATEST RESULT", 18, PINK);
        output = label(diagnostics, "Select profiles, preview and connect, then audit "
                + "routing. Any correction is a separate opt-in action. Remove owned "
                + "rules before disconnecting or changing tunnels.", 14, WHITE);
        updateButtons();
    }

    @Override protected void onResume() {
        super.onResume();
        reloadProfiles();
    }

    private void reloadProfiles() {
        List<String> checked = new ArrayList<>();
        for (Map.Entry<String, CheckBox> entry : selection.entrySet()) {
            if (entry.getValue().isChecked()) checked.add(entry.getKey());
        }
        try {
            List<SecureTunnelProfileStore.Profile> imported = store.load();
            saved.clear();
            saved.addAll(imported);
            selection.clear();
            profileRows.removeAllViews();
            for (SecureTunnelProfileStore.Profile profile : saved) {
                CheckBox checkbox = new CheckBox(this);
                checkbox.setText(profile.name + "  ·  " + routeLabel(profile.routeMode));
                checkbox.setTextColor(WHITE);
                checkbox.setTextSize(15);
                checkbox.setPadding(dp(4), dp(8), dp(4), dp(8));
                checkbox.setButtonTintList(android.content.res.ColorStateList.valueOf(PINK));
                checkbox.setChecked(checked.contains(profile.name));
                checkbox.setOnCheckedChangeListener((button, isChecked) -> updateButtons());
                profileRows.addView(checkbox);
                selection.put(profile.name, checkbox);
            }
            if (saved.isEmpty()) label(profileRows, "Import a WireGuard .conf to begin.", 13, MUTED);
        } catch (Exception unavailable) {
            saved.clear();
            selection.clear();
            profileRows.removeAllViews();
            label(profileRows, "Could not open encrypted profiles. Check Keystore availability.",
                    13, PINK);
        }
        updateButtons();
    }

    private String routeLabel(int routeMode) {
        if (routeMode == VpnRouteModes.HOME) return "split destinations";
        if (routeMode == VpnRouteModes.ALL) return "IPv4+IPv6 defaults";
        return "profile-defined routes";
    }

    private List<SecureTunnelProfileStore.Profile> selected() {
        List<SecureTunnelProfileStore.Profile> profiles = new ArrayList<>();
        for (SecureTunnelProfileStore.Profile profile : saved) {
            CheckBox checkbox = selection.get(profile.name);
            if (checkbox != null && checkbox.isChecked()) profiles.add(profile);
        }
        return profiles;
    }

    private interface Operation {
        void invoke(List<SecureTunnelProfileStore.Profile> selected, RootMultiKernelSession.Callback cb);
    }

    private void run(String action, boolean allowEmpty, Operation operation) {
        List<SecureTunnelProfileStore.Profile> list = selected();
        if (list.isEmpty() && !allowEmpty) {
            output.setText("Choose at least one encrypted profile.");
            return;
        }
        if (session.isBusy()) {
            output.setText("A root operation is still running. Try again after it finishes.");
            return;
        }
        journal.record("ACTION", action + " for " + list.size() + " selected profile(s)");
        output.setText("Working: " + action + "...");
        operation.invoke(list, (ok, result) -> {
            if (isFinishing() || isDestroyed()) return;
            output.setText((ok ? "COMPLETE\n" : "CHECK REQUIRED\n") + result);
            journal.record("RESULT", result);
            updateButtons();
        });
        updateButtons();
    }

    private void confirm(boolean starting) {
        List<SecureTunnelProfileStore.Profile> list = selected();
        if (list.isEmpty()) { output.setText("Select at least one profile first."); return; }
        new AlertDialog.Builder(this)
                .setTitle(starting ? "Connect selected tunnels?" : "Disconnect selected tunnels?")
                .setMessage(starting
                        ? "Wonhee will preflight all selected routes, refuse legacy pair "
                        + "collisions, and start only new uniquely named interfaces. "
                        + "Connection may change Internet routing; this is experimental "
                        + "and has NO kill switch. Keep USB ADB available."
                        : "Wonhee will verify the selected kernel interfaces against "
                        + "their saved public identities before stopping any. Other VPNs "
                        + "will be left alone. Regular Wi-Fi/cellular traffic may resume.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton(starting ? "Connect" : "Disconnect", (dialog, which) ->
                        run(starting ? "Connect multi-tunnel selection" : "Disconnect multi-tunnel selection",
                                false, starting ? session::connect : session::disconnect))
                .show();
    }

    private void updateButtons() {
        boolean ready = !session.isBusy() && !selected().isEmpty();
        if (connect != null) connect.setEnabled(ready);
        if (disconnect != null) disconnect.setEnabled(ready);
        if (preview != null) preview.setEnabled(ready);
        if (inspect != null) inspect.setEnabled(!session.isBusy());
        if (audit != null) audit.setEnabled(ready);
        if (apply != null) apply.setEnabled(ready);
        if (recover != null) recover.setEnabled(ready);
        if (guardReadiness != null) guardReadiness.setEnabled(ready);
        if (dnsAudit != null) dnsAudit.setEnabled(ready);
        if (remove != null) remove.setEnabled(!session.isBusy());
    }

    private LinearLayout card(LinearLayout parent) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(14), dp(14), dp(14), dp(14));
        card.setBackgroundColor(PANEL);
        LinearLayout.LayoutParams layout = new LinearLayout.LayoutParams(-1, -2);
        layout.topMargin = dp(16);
        parent.addView(card, layout);
        return card;
    }

    private TextView label(LinearLayout parent, String content, int size, int color) {
        TextView view = new TextView(this);
        view.setText(content);
        view.setTextColor(color);
        view.setTextSize(size);
        view.setPadding(0, dp(7), 0, dp(7));
        parent.addView(view);
        return view;
    }

    private Button button(LinearLayout parent, String title) {
        Button view = new Button(this);
        view.setText(title);
        view.setAllCaps(false);
        view.setTextSize(15);
        view.setTextColor(WHITE);
        view.setBackgroundTintList(android.content.res.ColorStateList.valueOf(0xff553659));
        // Allow long labels to wrap without clipping behind Android UI bars.
        view.setMinHeight(dp(56));
        view.setPadding(dp(12), dp(12), dp(12), dp(12));
        LinearLayout.LayoutParams layout = new LinearLayout.LayoutParams(-1, -2);
        layout.topMargin = dp(8);
        parent.addView(view, layout);
        return view;
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
