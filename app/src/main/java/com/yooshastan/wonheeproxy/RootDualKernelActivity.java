package com.yooshastan.wonheeproxy;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;

import com.wireguard.android.backend.WgQuickBackend;

import java.util.ArrayList;
import java.util.List;

/** Manually started isolated test UI; leaves the existing GoBackend path intact. */
public final class RootDualKernelActivity extends Activity {
    private static final int PINK = 0xfffbadd8;
    private static final int WHITE = 0xfff8f1f9;
    private static final int MUTED = 0xffc4b7c9;
    private static final int PANEL = 0xff242033;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final List<SecureTunnelProfileStore.Profile> saved = new ArrayList<>();
    private RootDualKernelSession dual;
    private Spinner homeChoice;
    private Spinner airChoice;
    private Button checkButton;
    private Button startButton;
    private Button stopButton;
    private TextView status;
    private boolean visible;
    private final Runnable poll = new Runnable() {
        @Override public void run() {
            if (!visible) return;
            if (dual.isManagingPair() && !dual.isBusy()) {
                dual.readStatus(message -> { if (visible) status.setText(message); });
            }
            refreshButtons();
            handler.postDelayed(this, 5000L);
        }
    };

    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        dual = RootDualKernelSession.get(this);
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(0xff12101d);
        LinearLayout column = new LinearLayout(this);
        column.setPadding(dp(18), dp(22), dp(18), dp(24));
        column.setOrientation(LinearLayout.VERTICAL);
        scroll.addView(column);
        setContentView(scroll);

        label(column, "WONHEE PROXY", 26, PINK);
        label(column, "MULTI-TUNNEL CONTROL  ·  ROOT PREVIEW", 12, MUTED);
        label(column, "Pixel 8a experiment · two active kernel WireGuard interfaces", 14, MUTED);
        label(column, "Home stays split-tunnel (10.6.0.0/24, 10.0.0.0/24). "
                + "AirVPN Europe supplies both IPv4 and IPv6 default routes. "
                + "Imported keys and saved profiles are not modified.", 14, WHITE);
        label(column, "The usual Wonhee VPN and Android Always-on/lockdown must be off "
                + "during this test. Kernel tunnels are NOT managed by Android VpnService. "
                + "No kill switch, reboot recovery or DNS-leak guarantee is provided. "
                + "Do not rely on this test for privacy-sensitive traffic.", 13, PINK);

        LinearLayout profiles = card(column);
        label(profiles, "SELECTED CONFIGURATIONS", 17, PINK);
        label(profiles, "Import several .conf files, then choose one Home split tunnel "
                + "and one internet exit. This preview activates two at a time; "
                + "additional concurrent tunnels need route validation.", 13, MUTED);
        Button importButton = button(profiles, "IMPORT / MANAGE .CONF FILES");
        importButton.setOnClickListener(v -> startActivity(new Intent(this, VpnActivity.class)));
        label(profiles, "Home / ASUS profile", 16, WHITE);
        homeChoice = new Spinner(this);
        profiles.addView(homeChoice);
        label(profiles, "Internet / AirVPN profile", 16, WHITE);
        airChoice = new Spinner(this);
        profiles.addView(airChoice);

        LinearLayout controls = card(column);
        label(controls, "KERNEL CONNECTION", 17, PINK);

        checkButton = button(controls, "CHECK ROOT + KERNEL TOOLS");
        checkButton.setOnClickListener(v -> {
            status.setText("Checking root access and bundled kernel tools...");
            refreshButtons();
            dual.checkRoot((ok, detail) -> {
                if (!isFinishing()) { status.setText(detail); refreshButtons(); }
            });
        });
        startButton = button(controls, "START SELECTED TUNNELS");
        startButton.setOnClickListener(v -> confirmStart());
        stopButton = button(controls, "STOP BOTH KERNEL TUNNELS");
        stopButton.setOnClickListener(v -> {
            status.setText("Stopping both Wonhee-owned kernel interfaces...");
            dual.stopPair((ok, detail) -> {
                if (!isFinishing()) { status.setText(detail); refreshButtons(); }
            });
            refreshButtons();
        });
        LinearLayout diagnostics = card(column);
        label(diagnostics, "CONNECTION DIAGNOSTICS", 17, PINK);
        status = label(diagnostics, "Ready for root preflight. Nothing has been started.", 14, WHITE);
        label(column, "Test from cellular: check that 10.0.0.169:4533 opens, "
                + "that public IPv4/IPv6 egress is AirVPN Europe, and that DNS resolves. "
                + "Check both fresh handshakes, then STOP BOTH. "
                + "If the app crashes, a kernel interface may remain: inspect the phone "
                + "with adb shell su -c 'ip -d link show type wireguard'.", 13, MUTED);

        reload();
        refreshButtons();
    }

    private void reload() {
        saved.clear();
        try { saved.addAll(new SecureTunnelProfileStore(this).load()); }
        catch (Exception ignored) { status.setText("Could not decrypt saved profiles on this device."); }
        List<String> names = new ArrayList<>();
        for (SecureTunnelProfileStore.Profile p : saved) names.add(p.name);
        ArrayAdapter<String> homeAdapter = new ArrayAdapter<>(
                this, android.R.layout.simple_spinner_item, names) {
            @Override public View getView(int position, View convertView, ViewGroup parent) {
                TextView text = (TextView) super.getView(position, convertView, parent);
                text.setTextColor(WHITE);
                return text;
            }
        };
        homeAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        ArrayAdapter<String> airAdapter = new ArrayAdapter<>(
                this, android.R.layout.simple_spinner_item, new ArrayList<>(names)) {
            @Override public View getView(int position, View convertView, ViewGroup parent) {
                TextView text = (TextView) super.getView(position, convertView, parent);
                text.setTextColor(WHITE);
                return text;
            }
        };
        airAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        homeChoice.setAdapter(homeAdapter);
        airChoice.setAdapter(airAdapter);
        int chosenHome = -1;
        int chosenInternet = -1;
        for (int i = 0; i < saved.size(); ++i) {
            if (saved.get(i).role == SecureTunnelProfileStore.Profile.ROLE_HOME) chosenHome = i;
            if (saved.get(i).role == SecureTunnelProfileStore.Profile.ROLE_INTERNET) chosenInternet = i;
        }
        for (int i = 0; i < saved.size(); ++i) {
            String name = saved.get(i).name.toLowerCase(java.util.Locale.ROOT);
            if (chosenHome < 0 && (name.contains("home") || name.contains("pixel")
                    || name.contains("asus") || name.contains("wgs_client"))) chosenHome = i;
            if (chosenInternet < 0 && (name.contains("air") || name.contains("europe")))
                chosenInternet = i;
        }
        if (chosenHome >= 0) homeChoice.setSelection(chosenHome);
        if (chosenInternet >= 0) airChoice.setSelection(chosenInternet);
    }

    private void confirmStart() {
        if (dual.isBusy() || dual.isManagingPair() || saved.size() < 2) return;
        if (!WgQuickBackend.hasKernelSupport()) {
            status.setText("No kernel WireGuard module available on this device.");
            return;
        }
        if (WireGuardSession.get(this).isConnected()) {
            status.setText("Disconnect the normal Wonhee VPN before starting rooted tunnels.");
            return;
        }
        int home = homeChoice.getSelectedItemPosition();
        int air = airChoice.getSelectedItemPosition();
        if (home < 0 || air < 0 || home >= saved.size() || air >= saved.size() || home == air) {
            status.setText("Choose two different saved WireGuard profiles.");
            return;
        }
        SecureTunnelProfileStore.Profile homeProfile = saved.get(home);
        SecureTunnelProfileStore.Profile airProfile = saved.get(air);
        new AlertDialog.Builder(this)
                .setTitle("Start two rooted kernel tunnels?")
                .setMessage("This runs two independent WireGuard profiles through kernel "
                        + "interfaces named wnhome0 and wnair0. Stop Android Always-on/lockdown "
                        + "first. Home MUST be split-routed; AirVPN MUST include IPv4 and IPv6 "
                        + "defaults. Your connection may drop. Root permission will be requested. "
                        + "This is an experimental connectivity test, not a verified kill switch.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Start test", (dialog, which) -> {
                    status.setText("Starting Home, then AirVPN Europe...");
                    dual.startPair(homeProfile, airProfile, (ok, detail) -> {
                        if (!isFinishing()) { status.setText(detail); refreshButtons(); }
                    });
                    refreshButtons();
                }).show();
    }

    private void refreshButtons() {
        if (startButton == null) return;
        boolean busy = dual.isBusy();
        boolean managing = dual.isManagingPair();
        checkButton.setEnabled(!busy && !managing);
        startButton.setEnabled(!busy && !managing && saved.size() >= 2);
        stopButton.setEnabled(!busy && managing);
        homeChoice.setEnabled(!busy && !managing);
        airChoice.setEnabled(!busy && !managing);
    }

    @Override protected void onResume() {
        super.onResume();
        if (status != null && !dual.isManagingPair()) reload();
        visible = true;
        handler.removeCallbacks(poll);
        handler.post(poll);
    }

    @Override protected void onPause() {
        visible = false;
        handler.removeCallbacks(poll);
        super.onPause();
    }

    private TextView label(LinearLayout parent, String value, int sp, int color) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(sp);
        view.setTextColor(color);
        view.setPadding(0, dp(9), 0, dp(9));
        parent.addView(view);
        return view;
    }

    private Button button(LinearLayout parent, String text) {
        Button result = new Button(this);
        result.setText(text);
        result.setTextColor(WHITE);
        result.setAllCaps(false);
        GradientDrawable background = new GradientDrawable();
        background.setColor(0xff483250);
        background.setCornerRadius(dp(12));
        result.setBackground(background);
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, dp(52));
        params.topMargin = dp(8);
        parent.addView(result, params);
        return result;
    }

    private LinearLayout card(LinearLayout parent) {
        LinearLayout result = new LinearLayout(this);
        result.setOrientation(LinearLayout.VERTICAL);
        result.setPadding(dp(16), dp(12), dp(16), dp(16));
        GradientDrawable background = new GradientDrawable();
        background.setColor(PANEL);
        background.setCornerRadius(dp(18));
        result.setBackground(background);
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        params.topMargin = dp(14);
        parent.addView(result, params);
        return result;
    }

    private int dp(float value) { return (int) (getResources().getDisplayMetrics().density * value); }
}
