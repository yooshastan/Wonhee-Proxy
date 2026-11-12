package com.yooshastan.wonheeproxy;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.ColorStateList;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.os.Build;
import android.view.View;
import android.view.WindowInsets;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.AdapterView;

import com.wireguard.config.Config;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Everyday per-profile editor. This screen never starts/stops a VPN, performs
 * root networking commands, displays private keys, or changes Android DNS.
 *
 * Edits are encrypted at rest using the existing SecureTunnelProfileStore and
 * refused unless currently known connection/ownership state is stopped.
 */
public final class TunnelProfileSettingsActivity extends Activity {
    static final String EXTRA_PROFILE_NAME = "wonhee.profile.name";

    private static final int BACKGROUND = 0xff15101e;
    private static final int SURFACE = 0xff2b2038;
    private static final int ALT = 0xff372845;
    private static final int PINK = 0xffffaddb;
    private static final int WHITE = 0xfffff7fd;
    private static final int MUTED = 0xffc9bed2;

    private SecureTunnelProfileStore store;
    private SecureTunnelProfileStore.Profile original;
    private Spinner route;
    private EditText privateRoutes;
    private Spinner dns;
    private EditText customDns;
    private TextView feedback;
    private boolean busy;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        store = new SecureTunnelProfileStore(this);
        final String requested = getIntent().getStringExtra(EXTRA_PROFILE_NAME);
        try {
            List<SecureTunnelProfileStore.Profile> saved = store.load();
            for (SecureTunnelProfileStore.Profile profile : saved) {
                if (profile.name.equals(requested)) {
                    original = profile;
                    break;
                }
            }
        } catch (Exception unavailable) {
            // No raw exception or encrypted config is shown.
        }
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(BACKGROUND);
        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setPadding(dp(18), dp(20), dp(18), dp(24));
        scroll.addView(page);
        scroll.setOnApplyWindowInsetsListener((v, insets) -> {
            if (Build.VERSION.SDK_INT >= 30) {
                android.graphics.Insets bars = insets.getInsets(
                        WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
                v.setPadding(bars.left, bars.top, bars.right, bars.bottom);
            } else {
                v.setPadding(insets.getSystemWindowInsetLeft(),
                        insets.getSystemWindowInsetTop(),
                        insets.getSystemWindowInsetRight(),
                        insets.getSystemWindowInsetBottom());
            }
            return insets;
        });
        setContentView(scroll);
        scroll.requestApplyInsets();

        text(page, "TUNNEL SETTINGS", 22, PINK);
        if (original == null) {
            text(page, "This saved tunnel is unavailable. Return to Home "
                    + "and refresh your profiles.", 15, WHITE);
            action(page, "Back to tunnels", this::finish);
            return;
        }
        text(page, original.name, 20, WHITE);
        text(page, "Settings for this tunnel only. Selection and Start/Stop "
                + "stay on Home.", 13, MUTED);
        LinearLayout editor = card(page);
        text(editor, "WHERE SHOULD IT CONNECT?", 13, PINK);
        route = select(editor, new String[]{
                "Use original WireGuard routes",
                "Private destinations (split routing)",
                "Internet exit (IPv4 + IPv6)"
        });
        route.setSelection(original.routeMode);

        text(editor, "Private network destinations", 12, MUTED);
        privateRoutes = new EditText(this);
        privateRoutes.setTextColor(WHITE);
        privateRoutes.setHintTextColor(MUTED);
        privateRoutes.setTextSize(14);
        privateRoutes.setHint("10.0.0.0/24, 10.6.0.0/24");
        privateRoutes.setMinLines(1);
        privateRoutes.setMaxLines(3);
        privateRoutes.setText(original.homeRoutes);
        editor.addView(privateRoutes);
        route.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> parent, View view,
                    int position, long id) {
                privateRoutes.setVisibility(position == VpnRouteModes.HOME
                        ? View.VISIBLE : View.GONE);
            }
            @Override public void onNothingSelected(AdapterView<?> parent) { }
        });

        text(editor, "DNS INSIDE THIS TUNNEL", 13, PINK);
        dns = select(editor, VpnDnsPresets.LABELS);
        customDns = new EditText(this);
        customDns.setSingleLine(true);
        customDns.setTextSize(14);
        customDns.setHint("DNS IP address(es)");
        customDns.setTextColor(WHITE);
        customDns.setHintTextColor(MUTED);
        int savedChoice = VpnDnsPresets.choiceForSaved(
                original.homeDnsEnabled, original.homeDnsServer);
        dns.setSelection(savedChoice);
        if (savedChoice == VpnDnsPresets.CUSTOM) {
            customDns.setText(original.homeDnsServer);
        }
        editor.addView(customDns);
        customDns.setVisibility(savedChoice == VpnDnsPresets.CUSTOM
                ? View.VISIBLE : View.GONE);
        dns.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> parent, View view,
                    int position, long id) {
                customDns.setVisibility(position == VpnDnsPresets.CUSTOM
                        ? View.VISIBLE : View.GONE);
            }
            @Override public void onNothingSelected(AdapterView<?> parent) { }
        });
        text(editor, "Changing a profile does not test its Internet or DNS "
                + "coverage. It does not change Android Private DNS.", 12, MUTED);

        Button save = action(editor, "Save settings", () ->
                verifyStopped(() -> new AlertDialog.Builder(this)
                        .setTitle("Save tunnel settings?")
                        .setMessage("The encrypted profile will be updated. "
                                + "These settings apply on the next connection; "
                                + "no VPN or firewall action happens now.")
                        .setNegativeButton("Cancel", null)
                        .setPositiveButton("Save", (d, w) -> verifyStopped(this::saveChanges))
                        .show()));
        save.setMinHeight(dp(58));
        Button delete = action(page, "Remove saved tunnel", () ->
                verifyStopped(() -> new AlertDialog.Builder(this)
                        .setTitle("Remove " + original.name + "?")
                        .setMessage("This permanently removes the saved encrypted "
                                + "profile from this app. Export a private backup "
                                + "first if you need it later. No active network "
                                + "interface will be changed.")
                        .setNegativeButton("Keep tunnel", null)
                        .setPositiveButton("Remove", (d, w) -> verifyStopped(this::deleteProfile))
                        .show()));
        delete.setTextColor(MUTED);
        delete.setBackground(tint(ALT));
        feedback = text(page, "For safety, disconnect and complete Safe Stop "
                + "before editing or removing a tunnel.", 12, MUTED);
        action(page, "Back to tunnels", this::finish);
    }

    private void verifyStopped(Runnable approved) {
        if (busy || isFinishing() || isDestroyed()) return;
        busy = true;
        boolean androidStopped;
        try {
            WireGuardSession vpn = WireGuardSession.get(this);
            androidStopped = !vpn.isConnected() && !vpn.isBusy();
        } catch (Exception | LinkageError unavailable) {
            androidStopped = false;
        }
        if (!androidStopped) {
            blocked("The Android VPN is active or its status is unavailable. "
                    + "Disconnect it before editing this saved tunnel.");
            return;
        }
        SharedPreferences ui = getSharedPreferences(
                "wonhee_everyday_ui_v1", Context.MODE_PRIVATE);
        if (!ui.getBoolean("root_mode", false)) {
            // A user may switch to Standard view despite unverified old root
            // state. That UI choice must not authorize profile mutation.
            if (ui.getBoolean("root_state_unverified", false)) {
                blocked("Earlier rooted networking was not confirmed stopped. "
                        + "Verify Safe Stop before editing saved profiles.");
                return;
            }
            busy = false;
            approved.run();
            return;
        }
        RootMultiKernelSession root = RootMultiKernelSession.get(this);
        if (root.isBusy() || !"OFF".equals(root.dnsLedgerStatus())
                || !"OFF".equals(root.guardLedgerStatus())
                || !getSharedPreferences("wonhee_owned_split_routes", MODE_PRIVATE)
                        .getString("pending_or_installed_rules_v1", "").isEmpty()) {
            blocked("Root networking is busy or has recorded owned rules. "
                    + "Use Safe Stop and verify its cleanup first.");
            return;
        }
        root.readRootTrafficSnapshot(snapshot -> {
            if (isFinishing() || isDestroyed()) return;
            if (snapshot == null || !snapshot.rootsAvailable
                    || snapshot.presentTunnels != 0) {
                blocked("Root tunnel state is active or cannot be verified. "
                        + "Use Safe Stop and review the root connection status first.");
                return;
            }
            busy = false;
            approved.run();
        });
    }

    private void blocked(String reason) {
        busy = false;
        if (feedback != null) feedback.setText(reason);
        new AlertDialog.Builder(this).setTitle("Finish disconnecting first")
                .setMessage(reason)
                .setPositiveButton("OK", null).show();
    }

    private void saveChanges() {
        if (original == null) return;
        try {
            // Re-read encrypted storage; a concurrent edit must not be silently
            // overwritten by this older UI snapshot.
            SecureTunnelProfileStore.Profile current = currentProfile();
            if (!sameProfile(current, original)) {
                blocked("The saved tunnel changed while this screen was open. "
                        + "Return to Tunnels and open it again.");
                return;
            }
            byte[] raw = original.configuration.getBytes(StandardCharsets.UTF_8);
            Config parsed;
            try {
                parsed = Config.parse(new ByteArrayInputStream(raw));
            } finally {
                Arrays.fill(raw, (byte) 0);
            }
            int mode = route.getSelectedItemPosition();
            String routes = privateRoutes.getText().toString().trim();
            Config effective = VpnRouteModes.prepare(parsed, mode, routes);
            int preset = dns.getSelectedItemPosition();
            boolean override = VpnDnsPresets.isOverride(preset);
            String addresses = VpnDnsPresets.addresses(preset,
                    customDns.getText().toString());
            VpnDnsOverride.prepare(effective, override, addresses);
            int role = mode == VpnRouteModes.HOME
                    ? SecureTunnelProfileStore.Profile.ROLE_HOME
                    : mode == VpnRouteModes.ALL
                    ? SecureTunnelProfileStore.Profile.ROLE_INTERNET
                    : original.role; // Preserve imported-role semantics for PROFILE routes.
            SecureTunnelProfileStore.Profile updated =
                    new SecureTunnelProfileStore.Profile(original.name,
                            original.configuration, mode, routes,
                            override, addresses, role);
            store.save(updated);
            finish();
        } catch (Exception | LinkageError invalid) {
            if (feedback != null) feedback.setText("Could not validate routing, "
                    + "DNS or profile storage. No changes were saved.");
        }
    }

    private void deleteProfile() {
        try {
            if (!sameProfile(currentProfile(), original)) {
                blocked("Saved tunnel changed. Return to Tunnels and open it again.");
                return;
            }
            store.delete(original.name);
            SharedPreferences ui = getSharedPreferences(
                    "wonhee_everyday_ui_v1", Context.MODE_PRIVATE);
            Set<String> names = new LinkedHashSet<>(ui.getStringSet(
                    "last_quick_profiles", java.util.Collections.emptySet()));
            names.remove(original.name);
            ui.edit().putStringSet("last_quick_profiles", names).apply();
            finish();
        } catch (Exception | LinkageError unavailable) {
            if (feedback != null) feedback.setText(
                    "Could not remove this tunnel. No network actions were taken.");
        }
    }

    private SecureTunnelProfileStore.Profile currentProfile() throws Exception {
        for (SecureTunnelProfileStore.Profile entry : store.load()) {
            if (original.name.equals(entry.name)) return entry;
        }
        return null;
    }

    private static boolean sameProfile(SecureTunnelProfileStore.Profile a,
            SecureTunnelProfileStore.Profile b) {
        return a != null && b != null && a.name.equals(b.name)
                && a.configuration.equals(b.configuration)
                && a.routeMode == b.routeMode && a.role == b.role
                && a.homeRoutes.equals(b.homeRoutes)
                && a.homeDnsEnabled == b.homeDnsEnabled
                && a.homeDnsServer.equals(b.homeDnsServer);
    }

    private Spinner select(LinearLayout parent, String[] labels) {
        Spinner spinner = new Spinner(this);
        ArrayAdapter<String> adapter = new ArrayAdapter<String>(this,
                android.R.layout.simple_spinner_item, labels) {
            @Override public View getView(int position, View convert,
                    android.view.ViewGroup parentView) {
                View result = super.getView(position, convert, parentView);
                if (result instanceof TextView) {
                    ((TextView) result).setTextColor(WHITE);
                }
                return result;
            }
            @Override public View getDropDownView(int position, View convert,
                    android.view.ViewGroup parentView) {
                View result = super.getDropDownView(position, convert, parentView);
                if (result instanceof TextView) {
                    ((TextView) result).setTextColor(0xff15101e);
                }
                return result;
            }
        };
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinner.setAdapter(adapter);
        parent.addView(spinner);
        return spinner;
    }

    private LinearLayout card(LinearLayout parent) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(14), dp(12), dp(14), dp(12));
        card.setBackground(tint(SURFACE));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(-1, -2);
        params.topMargin = dp(12);
        parent.addView(card, params);
        return card;
    }

    private TextView text(LinearLayout parent, String label, int size, int color) {
        TextView view = new TextView(this);
        view.setText(label);
        view.setTextSize(size);
        view.setTextColor(color);
        view.setPadding(0, dp(6), 0, dp(6));
        parent.addView(view);
        return view;
    }

    private Button action(LinearLayout parent, String label, Runnable callback) {
        Button button = new Button(this);
        button.setAllCaps(false);
        button.setText(label);
        button.setTextSize(15);
        button.setTextColor(BACKGROUND);
        button.setBackground(tint(PINK));
        button.setMinHeight(dp(52));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
        lp.topMargin = dp(8);
        parent.addView(button, lp);
        button.setOnClickListener(v -> callback.run());
        return button;
    }

    private GradientDrawable tint(int color) {
        GradientDrawable shape = new GradientDrawable();
        shape.setColor(color);
        shape.setCornerRadius(dp(14));
        return shape;
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
