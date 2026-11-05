package com.yooshastan.wonheeproxy;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
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

        label(column, "ROOT DUAL-TUNNEL LAB", 24, PINK);
        label(column, "Pixel 8a experiment · two kernel WireGuard interfaces", 14, MUTED);
        label(column, "Home stays split-tunnel (10.6.0.0/24, 10.0.0.0/24). "
                + "AirVPN Europe supplies both IPv4 and IPv6 default routes. "
                + "Imported keys and saved profiles are not modified.", 14, WHITE);
        label(column, "The usual Wonhee VPN and Android Always-on/lockdown must be off "
                + "during this test. Kernel tunnels are NOT managed by Android VpnService. "
                + "No kill switch, reboot recovery or DNS-leak guarantee is provided. "
                + "Do not rely on this test for privacy-sensitive traffic.", 13, PINK);

        label(column, "Home / ASUS profile", 16, WHITE);
        homeChoice = new Spinner(this);
        column.addView(homeChoice);
        label(column, "AirVPN Europe profile", 16, WHITE);
        airChoice = new Spinner(this);
        column.addView(airChoice);

        checkButton = button(column, "Check root + kernel tools");
        checkButton.setOnClickListener(v -> {
            status.setText("Checking root access and bundled kernel tools...");
            refreshButtons();
            dual.checkRoot((ok, detail) -> {
                if (!isFinishing()) { status.setText(detail); refreshButtons(); }
            });
        });
        startButton = button(column, "START BOTH KERNEL TUNNELS");
        startButton.setOnClickListener(v -> confirmStart());
        stopButton = button(column, "STOP BOTH KERNEL TUNNELS");
        stopButton.setOnClickListener(v -> {
            status.setText("Stopping both Wonhee-owned kernel interfaces...");
            dual.stopPair((ok, detail) -> {
                if (!isFinishing()) { status.setText(detail); refreshButtons(); }
            });
            refreshButtons();
        });
        status = label(column, "Ready for root preflight. Nothing has been started.", 14, WHITE);
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
                this, android.R.layout.simple_spinner_item, names);
        homeAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        ArrayAdapter<String> airAdapter = new ArrayAdapter<>(
                this, android.R.layout.simple_spinner_item, new ArrayList<>(names));
        airAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        homeChoice.setAdapter(homeAdapter);
        airChoice.setAdapter(airAdapter);
        for (int i = 0; i < saved.size(); ++i) {
            String name = saved.get(i).name.toLowerCase(java.util.Locale.ROOT);
            if (name.contains("home") || name.contains("pixel") || name.contains("asus")) {
                homeChoice.setSelection(i);
            } else if (name.contains("air") || name.contains("europe")) {
                airChoice.setSelection(i);
            }
        }
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
        parent.addView(result);
        return result;
    }

    private int dp(float value) { return (int) (getResources().getDisplayMetrics().density * value); }
}
