package com.yooshastan.wonheeproxy;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
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
import java.util.Date;
import java.util.List;
import java.text.DateFormat;

/** Manually started isolated test UI; leaves the existing GoBackend path intact. */
public final class RootDualKernelActivity extends Activity {
    private static final int PINK = 0xfffbadd8;
    private static final int WHITE = 0xfff8f1f9;
    private static final int MUTED = 0xffc4b7c9;
    private static final int PANEL = 0xff242033;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final List<SecureTunnelProfileStore.Profile> saved = new ArrayList<>();
    private RootDualKernelSession dual;
    private RootLabPreferences uiPreferences;
    private Spinner homeChoice;
    private Spinner airChoice;
    private Button savePairButton;
    private Button checkButton;
    private Button startButton;
    private Button stopButton;
    private Button restartButton;
    private Button resumeButton;
    private Button refreshLiveButton;
    private Button recoverButton;
    private Button firewallPreflightButton;
    private Button guardReadinessButton;
    private Button dnsRouteCheckButton;
    private Button routeAuditButton;
    private Button interfaceInspectButton;
    private TextView status;
    private TextView liveStatus;
    private boolean visible;
    private final Runnable poll = new Runnable() {
        @Override public void run() {
            if (!visible) return;
            if (dual.isManagingPair() && !dual.isBusy()) {
                dual.readStatus(message -> { if (visible) liveStatus.setText(message); });
            }
            refreshButtons();
            handler.postDelayed(this, 5000L);
        }
    };

    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        dual = RootDualKernelSession.get(this);
        uiPreferences = new RootLabPreferences(this);
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

        // Keep the primary live status above the long diagnostic tool list.
        LinearLayout livePanel = card(column);
        label(livePanel, "LIVE HOME + INTERNET STATUS", 17, PINK);
        label(livePanel, "Individual speed, traffic total and handshake age. Refreshes "
                + "every 5 seconds while this process manages the pair.", 12, MUTED);
        liveStatus = label(livePanel, "Tap READ LIVE STATUS to inspect the two kernel "
                + "interfaces. If they survived an app restart, verify their identities "
                + "before resuming control.", 14, WHITE);
        refreshLiveButton = button(livePanel, "READ LIVE STATUS (NO CHANGES)");
        refreshLiveButton.setOnClickListener(v -> {
            liveStatus.setText("Reading kernel interface counters...");
            dual.inspectLiveStatus((ok, detail) -> {
                if (isFinishing()) return;
                liveStatus.setText(detail);
                if (!ok) publishResult(detail);
                refreshButtons();
            });
            refreshButtons();
        });
        resumeButton = button(livePanel, "VERIFY + RESUME EXISTING PAIR");
        resumeButton.setOnClickListener(v -> confirmResume());

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
        savePairButton = button(profiles, "SAVE SELECTED HOME + INTERNET PAIR");
        savePairButton.setOnClickListener(v -> {
            int homeIndex = homeChoice.getSelectedItemPosition();
            int internetIndex = airChoice.getSelectedItemPosition();
            if (homeIndex < 0 || internetIndex < 0 || homeIndex == internetIndex
                    || homeIndex >= saved.size() || internetIndex >= saved.size()) {
                publishResult("Choose two different profiles before saving the default pair.");
                return;
            }
            try {
                uiPreferences.savePair(saved.get(homeIndex).name, saved.get(internetIndex).name);
                publishResult("Saved default Home and Internet profile selections for this device. "
                        + "No WireGuard keys or routes were changed.");
            } catch (IllegalArgumentException invalid) {
                publishResult("The two selected entries need different saved profile names.");
            }
        });

        LinearLayout controls = card(column);
        label(controls, "KERNEL CONNECTION", 17, PINK);

        checkButton = button(controls, "CHECK ROOT + KERNEL TOOLS");
        checkButton.setOnClickListener(v -> {
            status.setText("Checking root access and bundled kernel tools...");
            refreshButtons();
            dual.checkRoot((ok, detail) -> {
                if (!isFinishing()) { publishResult(detail); refreshButtons(); }
            });
        });
        startButton = button(controls, "START SELECTED TUNNELS");
        startButton.setOnClickListener(v -> confirmStart());
        stopButton = button(controls, "STOP BOTH KERNEL TUNNELS");
        stopButton.setOnClickListener(v -> {
            status.setText("Stopping both Wonhee-owned kernel interfaces...");
            dual.stopPair((ok, detail) -> {
                if (!isFinishing()) {
                    publishResult(detail);
                    if (ok) liveStatus.setText("Both managed kernel tunnels stopped.");
                    refreshButtons();
                }
            });
            refreshButtons();
        });
        restartButton = button(controls, "RESTART MANAGED PAIR (CONFIRM)");
        restartButton.setOnClickListener(v -> confirmRestart());
        recoverButton = button(controls, "RECOVER MATCHING OLD INTERFACES");
        recoverButton.setOnClickListener(v -> confirmRecovery());
        LinearLayout privacy = card(column);
        label(privacy, "PRIVACY ENFORCEMENT LAB", 17, PINK);
        label(privacy, "No verified kernel kill switch is installed. The Android Always-on "
                + "lockdown setting does not protect this root-only test. Before enabling "
                + "firewall changes, verify IPv4, IPv6, encrypted transport exceptions, "
                + "DNS behavior, crash recovery and reboot state.", 13, MUTED);
        firewallPreflightButton = button(privacy, "CHECK FIREWALL CAPABILITIES (READ ONLY)");
        firewallPreflightButton.setOnClickListener(v -> {
            status.setText("Checking root firewall tools without installing rules...");
            dual.checkFirewallCapabilities((ok, detail) -> {
                if (!isFinishing()) { publishResult(detail); refreshButtons(); }
            });
            refreshButtons();
        });
        guardReadinessButton = button(privacy, "CHECK KILL-SWITCH ARMING READINESS (READ ONLY)");
        guardReadinessButton.setOnClickListener(v -> {
            status.setText("Checking transport marks, IPv4/IPv6 rules and safe chain ownership...");
            dual.checkGuardReadiness((ok, detail) -> {
                if (!isFinishing()) { publishResult(detail); refreshButtons(); }
            });
            refreshButtons();
        });
        dnsRouteCheckButton = button(privacy, "CHECK INTERNET DNS ROUTES (READ ONLY)");
        dnsRouteCheckButton.setOnClickListener(v -> {
            int selected = airChoice.getSelectedItemPosition();
            if (selected < 0 || selected >= saved.size()) {
                publishResult("Select an Internet profile before testing its DNS routes.");
                return;
            }
            status.setText("Checking configured DNS destination routes, not actual DNS traffic...");
            dual.checkInternetDnsRoutes(saved.get(selected), (ok, detail) -> {
                if (!isFinishing()) { publishResult(detail); refreshButtons(); }
            });
            refreshButtons();
        });
        routeAuditButton = button(privacy, "AUDIT PUBLIC / HOME ROUTES + ANDROID DNS");
        routeAuditButton.setOnClickListener(v -> {
            int homeIndex = homeChoice.getSelectedItemPosition();
            int internetIndex = airChoice.getSelectedItemPosition();
            if (homeIndex < 0 || internetIndex < 0 || homeIndex == internetIndex
                    || homeIndex >= saved.size() || internetIndex >= saved.size()) {
                publishResult("Select two different saved Home and Internet profiles first.");
                return;
            }
            status.setText("Auditing root route decisions and Android active-network DNS...");
            dual.auditCurrentRoutes(saved.get(homeIndex), saved.get(internetIndex), (ok, detail) -> {
                if (!isFinishing()) { publishResult(detail); refreshButtons(); }
            });
            refreshButtons();
        });
        interfaceInspectButton = button(privacy, "INSPECT KERNEL INTERFACES AFTER RESTART");
        interfaceInspectButton.setOnClickListener(v -> {
            status.setText("Checking for existing kernel interfaces without changing them...");
            dual.inspectKernelInterfaces((ok, detail) -> {
                if (!isFinishing()) { publishResult(detail); refreshButtons(); }
            });
            refreshButtons();
        });
        LinearLayout diagnostics = card(column);
        label(diagnostics, "CONNECTION DIAGNOSTICS", 17, PINK);
        label(diagnostics, "LAST TEST RESULT (SAVED BETWEEN APP RESTARTS)", 12, MUTED);
        String previous = uiPreferences.lastDiagnostic();
        long previousAt = uiPreferences.lastDiagnosticTime();
        String restored = previous.isEmpty() ? "Ready for root preflight. Nothing has been started."
                : "Previous result (" + DateFormat.getDateTimeInstance().format(new Date(previousAt))
                    + "):\n" + previous;
        status = label(diagnostics, restored, 14, WHITE);
        Button copyResult = button(diagnostics, "COPY LAST TEST RESULT");
        copyResult.setOnClickListener(v -> {
            ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (clipboard != null) {
                clipboard.setPrimaryClip(ClipData.newPlainText(
                        "Wonhee root diagnostic", status.getText()));
            }
        });
        Button copySnapshot = button(diagnostics, "COPY ROOT SUPPORT SNAPSHOT");
        copySnapshot.setOnClickListener(v -> {
            ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (clipboard == null) return;
            int homeIndex = homeChoice.getSelectedItemPosition();
            int internetIndex = airChoice.getSelectedItemPosition();
            String homeName = homeIndex >= 0 && homeIndex < saved.size()
                    ? saved.get(homeIndex).name : "none";
            String internetName = internetIndex >= 0 && internetIndex < saved.size()
                    ? saved.get(internetIndex).name : "none";
            String snapshot = "Wonhee root support snapshot\nHome profile: " + homeName
                    + "\nInternet profile: " + internetName
                    + "\n\nLive kernel status:\n" + liveStatus.getText()
                    + "\n\nLast diagnostic:\n" + status.getText();
            clipboard.setPrimaryClip(ClipData.newPlainText("Wonhee root support snapshot", snapshot));
        });
        Button forgetResult = button(diagnostics, "CLEAR SAVED DIAGNOSTIC");
        forgetResult.setOnClickListener(v -> {
            uiPreferences.clearDiagnostic();
            status.setText("Saved diagnostic cleared. No tunnel configuration changed.");
        });
        label(diagnostics, "The live pair dashboard is at the top of this screen. "
                + "A long handshake age can mean an idle tunnel; it is not "
                + "proof that the connection has failed. Counters are not whole-device "
                + "traffic or a DNS/leak audit.", 12, MUTED);
        label(diagnostics, "Copying a result places it on Android's clipboard. It contains "
                + "no private WireGuard keys, but other apps may read clipboard content.",
                12, MUTED);
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
        catch (Exception ignored) { publishResult("Could not decrypt saved profiles on this device."); }
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
        String preferredHome = uiPreferences.homeName();
        String preferredInternet = uiPreferences.internetName();
        for (int i = 0; i < saved.size(); ++i) {
            if (saved.get(i).name.equals(preferredHome)) chosenHome = i;
            if (saved.get(i).name.equals(preferredInternet)) chosenInternet = i;
        }
        for (int i = 0; i < saved.size(); ++i) {
            if (chosenHome < 0 && saved.get(i).role == SecureTunnelProfileStore.Profile.ROLE_HOME)
                chosenHome = i;
            if (chosenInternet < 0
                    && saved.get(i).role == SecureTunnelProfileStore.Profile.ROLE_INTERNET)
                chosenInternet = i;
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
            publishResult("No kernel WireGuard module available on this device.");
            return;
        }
        if (WireGuardSession.get(this).isConnected()) {
            publishResult("Disconnect the normal Wonhee VPN before starting rooted tunnels.");
            return;
        }
        int home = homeChoice.getSelectedItemPosition();
        int air = airChoice.getSelectedItemPosition();
        if (home < 0 || air < 0 || home >= saved.size() || air >= saved.size() || home == air) {
            publishResult("Choose two different saved WireGuard profiles.");
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
                        if (!isFinishing()) { publishResult(detail); refreshButtons(); }
                    });
                    refreshButtons();
                }).show();
    }

    private void confirmRecovery() {
        if (dual.isBusy() || dual.isManagingPair()) return;
        int homeIndex = homeChoice.getSelectedItemPosition();
        int internetIndex = airChoice.getSelectedItemPosition();
        if (homeIndex < 0 || internetIndex < 0 || homeIndex == internetIndex
                || homeIndex >= saved.size() || internetIndex >= saved.size()) {
            publishResult("Select two distinct saved profiles before recovery.");
            return;
        }
        SecureTunnelProfileStore.Profile selectedHome = saved.get(homeIndex);
        SecureTunnelProfileStore.Profile selectedAir = saved.get(internetIndex);
        new AlertDialog.Builder(this)
                .setTitle("Stop matching orphaned interfaces?")
                .setMessage("Recovery can disconnect your home and internet tunnels. "
                        + "Wonhee will verify the interface AND peer public keys against "
                        + "your selected saved profiles before stopping either interface. "
                        + "Unknown interfaces will not be changed. There is no verified "
                        + "kill switch, so ordinary traffic may use cellular afterward. "
                        + "Start the tunnels again manually after recovery.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Verify and stop", (dialog, which) -> {
                    status.setText("Checking old kernel identities before any cleanup...");
                    dual.recoverMatchingPair(selectedHome, selectedAir, (ok, detail) -> {
                        if (!isFinishing()) { publishResult(detail); refreshButtons(); }
                    });
                    refreshButtons();
                }).show();
    }

    /** User-initiated recovery only. Never silently bring up old kernel routes. */
    private void confirmRestart() {
        if (dual.isBusy() || !dual.isManagingPair()) return;
        int homeIndex = homeChoice.getSelectedItemPosition();
        int internetIndex = airChoice.getSelectedItemPosition();
        if (homeIndex < 0 || internetIndex < 0 || homeIndex == internetIndex
                || homeIndex >= saved.size() || internetIndex >= saved.size()) {
            publishResult("Select two different stored profiles to restart the active pair.");
            return;
        }
        SecureTunnelProfileStore.Profile selectedHome = saved.get(homeIndex);
        SecureTunnelProfileStore.Profile selectedInternet = saved.get(internetIndex);
        new AlertDialog.Builder(this)
                .setTitle("Manually restart both kernel tunnels?")
                .setMessage("Wonhee will first stop the currently managed pair, then "
                        + "start the selected Home and Internet profiles only if BOTH "
                        + "interfaces stopped. Internet and Navidrome access may be interrupted. "
                        + "If the restart fails, ordinary cellular traffic may resume: "
                        + "NO kernel kill switch is installed. Automatic recovery is OFF.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Restart pair", (dialog, which) -> {
                    status.setText("Stopping both managed tunnels before manual restart...");
                    dual.stopPair((stopped, stopDetail) -> {
                        if (isFinishing()) return;
                        if (!stopped) {
                            publishResult("Restart aborted: " + stopDetail
                                    + " No new tunnel start was attempted.");
                            refreshButtons();
                            return;
                        }
                        status.setText("Old pair stopped; starting selected pair...");
                        dual.startPair(selectedHome, selectedInternet, (started, startDetail) -> {
                            if (isFinishing()) return;
                            publishResult((started ? "Manual restart completed. "
                                    : "Manual restart failed after stopping old pair. ")
                                    + startDetail);
                            liveStatus.setText(started ? "Pair restarted. Measuring fresh "
                                    + "traffic and handshakes..." : "Pair restart failed. "
                                    + "Read live status to inspect remaining interfaces.");
                            refreshButtons();
                        });
                        refreshButtons();
                    });
                    refreshButtons();
                }).show();
    }

    private void confirmResume() {
        if (dual.isBusy() || dual.isManagingPair()) return;
        int homeIndex = homeChoice.getSelectedItemPosition();
        int internetIndex = airChoice.getSelectedItemPosition();
        if (homeIndex < 0 || internetIndex < 0 || homeIndex == internetIndex
                || homeIndex >= saved.size() || internetIndex >= saved.size()) {
            publishResult("Select different Home and Internet profiles first.");
            return;
        }
        SecureTunnelProfileStore.Profile selectedHome = saved.get(homeIndex);
        SecureTunnelProfileStore.Profile selectedInternet = saved.get(internetIndex);
        new AlertDialog.Builder(this)
                .setTitle("Resume control of existing kernel tunnels?")
                .setMessage("If both interfaces survived an app restart, Wonhee will "
                        + "verify their WireGuard public identities, peers, and Home/Internet "
                        + "routes against the profiles you selected. Nothing is modified "
                        + "by this verification. If every check passes, the app can "
                        + "monitor and manually restart that existing pair.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Verify and resume", (dialog, which) -> {
                    status.setText("Verifying existing kernel identities and routes...");
                    dual.verifyAndResumePair(selectedHome, selectedInternet, (ok, detail) -> {
                        if (isFinishing()) return;
                        publishResult(detail);
                        liveStatus.setText(ok ? "Verified active pair. Measuring live "
                                + "traffic now..." : "Unable to resume; "
                                + "tap READ LIVE STATUS for a read-only snapshot.");
                        refreshButtons();
                    });
                    refreshButtons();
                }).show();
    }

    private void refreshButtons() {
        if (startButton == null) return;
        boolean busy = dual.isBusy();
        boolean managing = dual.isManagingPair();
        savePairButton.setEnabled(!busy && !managing && saved.size() >= 2);
        checkButton.setEnabled(!busy && !managing);
        startButton.setEnabled(!busy && !managing && saved.size() >= 2);
        stopButton.setEnabled(!busy && managing);
        restartButton.setEnabled(!busy && managing && saved.size() >= 2);
        resumeButton.setEnabled(!busy && !managing && saved.size() >= 2);
        refreshLiveButton.setEnabled(!busy);
        recoverButton.setEnabled(!busy && !managing && saved.size() >= 2);
        firewallPreflightButton.setEnabled(!busy);
        guardReadinessButton.setEnabled(!busy);
        dnsRouteCheckButton.setEnabled(!busy && !saved.isEmpty());
        routeAuditButton.setEnabled(!busy && saved.size() >= 2);
        interfaceInspectButton.setEnabled(!busy);
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

    private void publishResult(String result) {
        status.setText(result);
        uiPreferences.saveDiagnostic(result);
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
