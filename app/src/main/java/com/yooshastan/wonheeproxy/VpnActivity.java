package com.yooshastan.wonheeproxy;

import android.app.Activity;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.app.AlertDialog;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.net.VpnService;
import android.provider.Settings;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;

import com.wireguard.config.Config;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * Alpha 0.8.6 preview: local traffic history, VPN route observations and encrypted
 * connection settings, routing choices and diagnostics. No fail-closed
 * protection is claimed. Telegram proxy tools remain in MainActivity.
 */
public final class VpnActivity extends Activity {
    private static final int PICK_CONFIG = 4201;
    private static final int VPN_PERMISSION = 4202;
    private static final int NOTIFICATION_PERMISSION = 4203;
    private static final int PINK = 0xfffbadd8;
    private static final int WHITE = 0xfff8f1f9;
    private static final int MUTED = 0xffc4b7c9;
    private static final long POLL_INTERVAL_MS = 5000L;
    private final Handler pollHandler = new Handler(Looper.getMainLooper());
    private final List<SecureTunnelProfileStore.Profile> profiles = new ArrayList<>();
    private final TunnelTrafficHistory trafficHistory = new TunnelTrafficHistory();
    private WireGuardSession session;
    private SecureTunnelProfileStore profileStore;
    private Config selectedConfig;
    private Config pendingConnection;
    private boolean updatingList;
    private boolean visible;
    private boolean statisticsPending;
    private boolean diagnosticsRunning;
    private Spinner savedPicker;
    private Spinner routingPicker;
    private EditText homeRoutes;
    private Spinner dnsPicker;
    private EditText customDnsAddresses;
    private TextView dnsStatus;
    private EditText profileName;
    private TextView connectionStatus;
    private TextView message;
    private TextView routeStatus;
    private TextView statisticsText;
    private TextView trafficSummary;
    private TunnelTrafficGraphView trafficGraph;
    private TextView healthStatus;
    private TextView diagnosticsReport;
    private Button diagnosticsButton;
    private Button vpnToggleButton, importButton, saveButton, deleteButton;

    private final Runnable poll = new Runnable() {
        @Override public void run() {
            if (!visible) return;
            if (session != null && !statisticsPending) {
                statisticsPending = true;
                session.readStatistics(snapshot -> {
                    statisticsPending = false;
                    if (!visible || isFinishing() || isDestroyed()) return;
                    renderStatistics(snapshot);
                    refreshButtons();
                });
            }
            pollHandler.postDelayed(this, POLL_INTERVAL_MS);
        }
    };

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        profileStore = new SecureTunnelProfileStore(this);
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(0xff12101d);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(20), dp(24), dp(20), dp(30));
        scroll.addView(root);
        setContentView(scroll);

        label(root, "WONHEE PROXY", 28, PINK);
        label(root, "WireGuard VPN · Alpha 0.8.6 preview", 15, MUTED);

        LinearLayout dashboard = card(root);
        connectionStatus = label(dashboard, "Disconnected", 22, WHITE);
        statisticsText = label(dashboard, "No tunnel active.", 14, MUTED);
        vpnToggleButton = button(dashboard, "Turn VPN On");
        vpnToggleButton.setOnClickListener(v -> {
            if (session == null || session.isBusy()) return;
            if (session.isConnected()) stopTunnel();
            else confirmConnect();
        });
        label(dashboard, "The silent Wonhee notification shows tunnel download/upload speeds while VPN is active. Allow notifications when Android asks. Speeds are not a traffic leak test.", 12, MUTED);
        label(dashboard, "VPN interface and handshake are different states. A handshake does not prove DNS or full-device leak protection.", 12, MUTED);

        LinearLayout trafficCard = card(root);
        label(trafficCard, "LIVE TUNNEL TRAFFIC", 17, PINK);
        trafficSummary = label(trafficCard,
                "Waiting for two WireGuard counter samples...", 14, WHITE);
        trafficGraph = new TunnelTrafficGraphView(this);
        trafficCard.addView(trafficGraph, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, dp(150)));
        label(trafficCard, "Blue = download · Pink = upload · Last ~2 minutes while open. "
                + "These are VPN tunnel counter deltas, not a whole-device speed test "
                + "or proof against traffic leaks.", 12, MUTED);

        LinearLayout healthCard = card(root);
        label(healthCard, "CONNECTION HEALTH", 17, PINK);
        healthStatus = label(healthCard, "Waiting for local VPN status...", 14, WHITE);
        diagnosticsButton = button(healthCard, "Run DNS & HTTPS test (example.com)");
        diagnosticsButton.setOnClickListener(v -> confirmDiagnostics());
        diagnosticsReport = label(healthCard, "No active network test has been run.", 13, MUTED);
        label(healthCard, "The test sends an explicit DNS lookup and HTTPS HEAD request only "
                + "on an Android-reported VPN network, with no normal-network fallback. "
                + "A successful test is not proof against DNS, IPv6 or traffic leaks.", 12, MUTED);

        LinearLayout configCard = card(root);
        label(configCard, "WIREGUARD PROFILES", 17, PINK);
        savedPicker = new Spinner(this);
        configCard.addView(savedPicker);
        savedPicker.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                if (updatingList || (session != null && session.isConnected())) return;
                if (position > 0 && position <= profiles.size()) {
                    loadSelected(profiles.get(position - 1));
                } else if (position == 0 && !profiles.isEmpty()) {
                    selectedConfig = null;
                    pendingConnection = null;
                    refreshRoutingPreview();
                    refreshButtons();
                }
            }
            @Override public void onNothingSelected(AdapterView<?> parent) { }
        });
        profileName = new EditText(this);
        profileName.setSingleLine(true);
        profileName.setTextColor(WHITE);
        profileName.setHintTextColor(MUTED);
        profileName.setHint("Profile name, e.g. Home VPN");
        configCard.addView(profileName);
        importButton = button(configCard, "Import WireGuard .conf");
        importButton.setOnClickListener(v -> chooseConfig());
        saveButton = button(configCard, "Save profile settings");
        saveButton.setOnClickListener(v -> saveSelected());
        deleteButton = button(configCard, "Delete selected profile");
        deleteButton.setOnClickListener(v -> confirmDelete());
        LinearLayout routingCard = card(root);
        label(routingCard, "CONNECTION ROUTING", 17, PINK);
        label(routingCard, "Choose where the phone sends traffic when you connect.", 13, MUTED);
        routingPicker = new Spinner(this);
        ArrayAdapter<String> routingAdapter = new ArrayAdapter<String>(this,
                android.R.layout.simple_spinner_item,
                new String[] {
                        "Use profile routes (unchanged)",
                        "Home access (split routes)",
                        "All internet (experimental)"
                }) {
            @Override public View getView(int position, View convertView,
                                          android.view.ViewGroup parent) {
                View row = super.getView(position, convertView, parent);
                if (row instanceof TextView) ((TextView) row).setTextColor(WHITE);
                return row;
            }
            @Override public View getDropDownView(int position, View convertView,
                                                  android.view.ViewGroup parent) {
                View row = super.getDropDownView(position, convertView, parent);
                if (row instanceof TextView) ((TextView) row).setTextColor(Color.BLACK);
                return row;
            }
        };
        routingAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        routingPicker.setAdapter(routingAdapter);
        routingCard.addView(routingPicker);
        homeRoutes = new EditText(this);
        homeRoutes.setSingleLine(true);
        homeRoutes.setTextColor(WHITE);
        homeRoutes.setHintTextColor(MUTED);
        homeRoutes.setHint("Home CIDRs, e.g. 10.77.0.0/24, 192.168.50.0/24");
        routingCard.addView(homeRoutes);
        homeRoutes.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence text, int start, int count, int after) { }
            @Override public void onTextChanged(CharSequence text, int start, int before, int count) { }
            @Override public void afterTextChanged(Editable text) { refreshRoutingPreview(); }
        });
        routeStatus = label(routingCard, "Import or choose a saved configuration.", 13, MUTED);
        routingPicker.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> parent, View view, int pos, long id) {
                refreshRoutingPreview();
            }
            @Override public void onNothingSelected(AdapterView<?> parent) { }
        });
        label(routingCard, "Imported keys are saved securely right away. "
                + "Connecting automatically saves routing and DNS choices. "
                + "Use Save profile settings to save without connecting.", 12, MUTED);

        LinearLayout dnsCard = card(root);
        label(dnsCard, "DNS RESOLVERS", 17, PINK);
        label(dnsCard, "Choose a DNS preset for this encrypted WireGuard profile.", 13, MUTED);
        dnsPicker = new Spinner(this);
        ArrayAdapter<String> dnsAdapter = new ArrayAdapter<String>(this,
                android.R.layout.simple_spinner_item, VpnDnsPresets.LABELS) {
            @Override public View getView(int position, View convertView,
                                          android.view.ViewGroup parent) {
                View row = super.getView(position, convertView, parent);
                if (row instanceof TextView) ((TextView) row).setTextColor(WHITE);
                return row;
            }
            @Override public View getDropDownView(int position, View convertView,
                                                  android.view.ViewGroup parent) {
                View row = super.getDropDownView(position, convertView, parent);
                if (row instanceof TextView) ((TextView) row).setTextColor(Color.BLACK);
                return row;
            }
        };
        dnsAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        dnsPicker.setAdapter(dnsAdapter);
        dnsCard.addView(dnsPicker);
        customDnsAddresses = new EditText(this);
        customDnsAddresses.setSingleLine(true);
        customDnsAddresses.setTextColor(WHITE);
        customDnsAddresses.setHintTextColor(MUTED);
        customDnsAddresses.setHint("One or two IPs, separated by a comma");
        dnsCard.addView(customDnsAddresses);
        dnsStatus = label(dnsCard, "Choose a saved configuration.", 13, MUTED);
        dnsPicker.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> parent, View view, int pos, long id) {
                refreshDnsPreview();
            }
            @Override public void onNothingSelected(AdapterView<?> parent) { }
        });
        customDnsAddresses.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence text, int start, int count, int after) { }
            @Override public void onTextChanged(CharSequence text, int start, int before, int count) { }
            @Override public void afterTextChanged(Editable text) { refreshDnsPreview(); }
        });
        refreshDnsPreview();
        label(dnsCard, "DNS is routed inside WireGuard when AllowedIPs cover the selected "
                + "addresses. Public presets do not add DoH/DoQ; provider-specific filtering "
                + "is not a full tracker or DNS-leak protection audit.", 12, MUTED);

        LinearLayout alwaysOnCard = card(root);
        label(alwaysOnCard, "PERSISTENT VPN & TRAFFIC BLOCKING", 17, PINK);
        label(alwaysOnCard, "Android controls Always-on VPN and Block connections without VPN. "
                + "These settings restore your last saved tunnel after an ordinary restart, "
                + "but Force stop can stop the VPN until you reopen the app.", 13, MUTED);
        Button androidVpnSettings = button(alwaysOnCard, "Open Android VPN settings");
        androidVpnSettings.setOnClickListener(v -> openSystemVpnSettings());
        label(alwaysOnCard, "CAUTION: Block connections without VPN may disable all internet "
                + "access while the VPN is unavailable or while Fedora lacks full-tunnel "
                + "forwarding, IPv6 routing or working DNS. Leave it off until tested.", 12, MUTED);

        message = label(root, "VPN is off. Import a profile once; the app will save it securely.", 14, WHITE);
        Button proxyTools = button(root, "Telegram proxy tools");
        proxyTools.setOnClickListener(v -> startActivity(new Intent(this, MainActivity.class)));
        label(root, "Security: imported VPN profiles are encrypted at rest with Android Keystore "
                + "and never uploaded or logged. Force stop does not delete saved profiles, "
                + "but uninstalling or replacing a differently signed debug APK may. "
                + "Back up the original .conf privately.", 12, MUTED);
        label(root, "Preview limitations: Android Always-on restoration is experimental and "
                + "must be tested after reboot and network changes. There is no independent "
                + "kill switch, in-app DoH/DoQ, tracker filtering or verified DNS/IPv6 leak "
                + "protection. Starting this VPN replaces Tailscale or another Android VPN.", 12, MUTED);

        try {
            session = WireGuardSession.get(this);
        } catch (RuntimeException | LinkageError unavailable) {
            message.setText("WireGuard engine is unavailable on this device.");
        }
        reloadProfiles(null);
        refreshButtons();
    }

    @Override protected void onResume() {
        super.onResume();
        visible = true;
        refreshButtons();
        if (session != null && session.isConnected()) {
            VpnTrafficNotificationService.startIfPossible(this);
        }
        pollHandler.removeCallbacks(poll);
        pollHandler.post(poll);
    }

    @Override protected void onPause() {
        visible = false;
        pollHandler.removeCallbacks(poll);
        trafficHistory.pause();
        super.onPause();
    }

    private void renderStatistics(WireGuardSession.StatusSnapshot snapshot) {
        refreshPassiveHealth(snapshot);
        if (!snapshot.interfaceUp) {
            trafficHistory.clear();
            trafficGraph.setValues(trafficHistory.values());
            trafficSummary.setText("No active tunnel; no traffic data.");
            connectionStatus.setText("Disconnected");
            connectionStatus.setTextColor(WHITE);
            statisticsText.setText("No tunnel active.");
            return;
        }
        if (!snapshot.statisticsAvailable) {
            trafficHistory.clear();
            trafficGraph.setValues(trafficHistory.values());
            trafficSummary.setText("WireGuard transfer counters unavailable.");
            connectionStatus.setText("Interface active");
            statisticsText.setText("Peer statistics unavailable. Check the Fedora gateway.");
            return;
        }
        long handshake = snapshot.lastHandshakeEpochMillis;
        long ageSeconds = handshake <= 0 ? -1 :
                Math.max(0L, (System.currentTimeMillis() - handshake) / 1000L);
        if (ageSeconds < 0) {
            connectionStatus.setText("Waiting for handshake");
            connectionStatus.setTextColor(PINK);
        } else if (ageSeconds <= 180L) {
            connectionStatus.setText("WireGuard peer responding");
            connectionStatus.setTextColor(0xffa6ebc4);
        } else {
            connectionStatus.setText("Handshake may be stale");
            connectionStatus.setTextColor(0xffffc6b0);
        }
        String handshakeText = ageSeconds < 0 ? "None yet"
                : (ageSeconds < 60 ? ageSeconds + " seconds ago"
                : (ageSeconds / 60) + " minutes ago");
        statisticsText.setText("Last handshake: " + handshakeText
                + "\nReceived: " + formatBytes(snapshot.receivedBytes)
                + " · Sent: " + formatBytes(snapshot.transmittedBytes)
                + "\nPeers tracked: " + snapshot.peers);
        TunnelTrafficRates.Result rate = trafficHistory.add(
                SystemClock.elapsedRealtime(), snapshot.receivedBytes,
                snapshot.transmittedBytes);
        trafficSummary.setText(rate == null
                ? "Collecting two live counter samples..."
                : "↓ " + TunnelTrafficRates.formatSpeed(rate.downloadMbps)
                + " · ↑ " + TunnelTrafficRates.formatSpeed(rate.uploadMbps)
                + "\nObserved peak ↓ "
                + TunnelTrafficRates.formatSpeed(trafficHistory.peakDownloadMbps())
                + " · ↑ "
                + TunnelTrafficRates.formatSpeed(trafficHistory.peakUploadMbps()));
        trafficGraph.setValues(trafficHistory.values());
    }

    private void refreshPassiveHealth(WireGuardSession.StatusSnapshot snapshot) {
        if (healthStatus == null || session == null) return;
        boolean dnsPresent = false;
        if (selectedConfig != null) {
            try {
                Config routed = VpnRouteModes.prepare(selectedConfig,
                        routingPicker.getSelectedItemPosition(), homeRoutes.getText().toString());
                Config ready = VpnDnsOverride.prepare(
                        routed, dnsOverrideEnabled(), chosenDnsAddresses());
                dnsPresent = VpnDnsOverride.hasDns(ready);
            } catch (Exception invalid) {
                // No configuration content or private-key exceptions are shown.
            }
        }
        long age = snapshot.lastHandshakeEpochMillis <= 0 ? -1L
                : Math.max(0L, (System.currentTimeMillis()
                        - snapshot.lastHandshakeEpochMillis) / 1000L);
        healthStatus.setText(VpnHealthSummary.render(snapshot.interfaceUp,
                snapshot.statisticsAvailable, age, dnsPresent,
                session.isAlwaysOn(), session.isLockdownEnabled()));
    }

    private void confirmDiagnostics() {
        if (session == null || !session.isConnected() || session.isBusy()) {
            diagnosticsReport.setText("Connect WireGuard before running a VPN-bound test.");
            return;
        }
        new AlertDialog.Builder(this)
                .setTitle("Test connection through Android VPN?")
                .setMessage("Wonhee will resolve example.com and send one HTTPS HEAD request "
                        + "through the Android-reported VPN network. No WireGuard keys or "
                        + "proxy credentials are sent. This tests reachability, not leak freedom.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Run test", (dialog, which) -> runDiagnostics())
                .show();
    }

    private void runDiagnostics() {
        if (diagnosticsRunning || session == null || !session.isConnected()) return;
        diagnosticsRunning = true;
        diagnosticsReport.setText("Testing VPN-bound DNS and HTTPS on example.com...");
        refreshButtons();
        VpnConnectionDiagnostics.run(this, report -> {
            diagnosticsRunning = false;
            if (isFinishing() || isDestroyed()) return;
            String note = session == null || !session.isConnected()
                    ? "VPN disconnected during the test; result may be stale.\n" : "";
            diagnosticsReport.setText(note + report);
            refreshButtons();
        });
    }

    private static String formatBytes(long count) {
        if (count < 1024) return count + " B";
        double number = count;
        String[] units = {"B", "KiB", "MiB", "GiB", "TiB"};
        int index = 0;
        while (number >= 1024 && index < units.length - 1) {
            number /= 1024;
            index++;
        }
        return String.format(Locale.US, "%.1f %s", number, units[index]);
    }

    private void chooseConfig() {
        if (session != null && session.isConnected()) {
            message.setText("Disconnect before importing or changing profiles.");
            return;
        }
        Intent picker = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        picker.addCategory(Intent.CATEGORY_OPENABLE);
        picker.setType("*/*");
        startActivityForResult(picker, PICK_CONFIG);
    }

    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request == PICK_CONFIG) {
            if (result != RESULT_OK || data == null || data.getData() == null) return;
            try {
                Config imported = readConfiguration(data.getData());
                selectedConfig = imported;
                pendingConnection = null;
                routingPicker.setSelection(VpnRouteModes.PROFILE);
                homeRoutes.setText(VpnRouteModes.suggestedHomeRoutes(imported));
                dnsPicker.setSelection(VpnDnsPresets.IMPORTED);
                customDnsAddresses.setText("");
                String importedName = availableImportName();
                profileName.setText(importedName);
                refreshRoutingPreview();
                try {
                    SecureTunnelProfileStore.Profile saved =
                            new SecureTunnelProfileStore.Profile(importedName,
                                    imported.toWgQuickString(),
                                    VpnRouteModes.PROFILE,
                                    homeRoutes.getText().toString());
                    profileStore.save(saved);
                    reloadProfiles(saved.name);
                    message.setText("WireGuard profile imported and saved securely. "
                            + "You can reconnect after closing or force-stopping the app.");
                } catch (Exception storageFailure) {
                    message.setText("Configuration imported, but secure storage FAILED. "
                            + "Do not force-stop until you correct storage and tap Save settings.");
                }
            } catch (Exception | LinkageError invalid) {
                selectedConfig = null;
                pendingConnection = null;
                refreshRoutingPreview();
                message.setText("Invalid WireGuard .conf. Check its interface, peer and key fields. Secrets and detailed parse errors are not logged.");
            }
            refreshButtons();
        } else if (request == VPN_PERMISSION) {
            if (result == RESULT_OK && VpnService.prepare(this) == null) {
                startTunnel();
            } else {
                pendingConnection = null;
                message.setText("Android VPN permission was not granted.");
            }
        }
    }

    private String availableImportName() {
        String requested = profileName.getText().toString().trim();
        if (requested.isEmpty() || requested.length() > 64
                || requested.chars().anyMatch(c -> Character.isISOControl((char) c))) {
            requested = "Home WireGuard";
        }
        String candidate = requested;
        for (int suffix = 2; suffix < 100; suffix++) {
            boolean exists = false;
            for (SecureTunnelProfileStore.Profile profile : profiles) {
                if (profile.name.equalsIgnoreCase(candidate)) {
                    exists = true;
                    break;
                }
            }
            if (!exists) return candidate;
            String tail = " (" + suffix + ")";
            candidate = requested.substring(0, Math.min(requested.length(), 64 - tail.length()))
                    + tail;
        }
        throw new IllegalArgumentException("Too many similarly named VPN profiles.");
    }

    private void openSystemVpnSettings() {
        try {
            startActivity(new Intent(Settings.ACTION_VPN_SETTINGS));
        } catch (RuntimeException unavailable) {
            message.setText("Android VPN settings could not be opened. "
                    + "Open Settings > Network & internet > VPN manually.");
        }
    }

    private Config readConfiguration(Uri uri) throws Exception {
        try (InputStream source = getContentResolver().openInputStream(uri)) {
            if (source == null) throw new IOException("No document");
            ByteArrayOutputStream data = new ByteArrayOutputStream();
            byte[] chunk = new byte[4096];
            int read;
            while ((read = source.read(chunk)) != -1) {
                if (data.size() + read > SecureTunnelProfileStore.MAX_CONFIG_BYTES) {
                    throw new IOException("Configuration too large");
                }
                data.write(chunk, 0, read);
            }
            Arrays.fill(chunk, (byte) 0);
            byte[] contents = data.toByteArray();
            try {
                return validated(contents);
            } finally {
                Arrays.fill(contents, (byte) 0);
            }
        }
    }

    private static Config validated(byte[] contents) throws Exception {
        Config config = Config.parse(new ByteArrayInputStream(contents));
        if (config.getPeers().isEmpty() || config.getInterface().getAddresses().isEmpty()) {
            throw new IllegalArgumentException("Peer and address required");
        }
        return config;
    }

    private void loadSelected(SecureTunnelProfileStore.Profile profile) {
        // Reloading the already-selected profile is safe even if the VPN is UP.
        // The picker itself remains disabled during an active connection.
        try {
            byte[] raw = profile.configuration.getBytes(StandardCharsets.UTF_8);
            try {
                selectedConfig = validated(raw);
            } finally {
                Arrays.fill(raw, (byte) 0);
            }
            pendingConnection = null;
            profileName.setText(profile.name);
            routingPicker.setSelection(profile.routeMode);
            homeRoutes.setText(profile.homeRoutes.isEmpty()
                    ? VpnRouteModes.suggestedHomeRoutes(selectedConfig) : profile.homeRoutes);
            int savedDnsChoice = VpnDnsPresets.choiceForSaved(
                    profile.homeDnsEnabled, profile.homeDnsServer);
            customDnsAddresses.setText(savedDnsChoice == VpnDnsPresets.CUSTOM
                    ? profile.homeDnsServer : "");
            dnsPicker.setSelection(savedDnsChoice);
            refreshRoutingPreview();
            int index = savedPicker.getSelectedItemPosition() - 1;
            if (index >= 0 && index < profiles.size()) {
                try {
                    profileStore.rememberSelectedIndex(index);
                } catch (Exception selectionSaveFailure) {
                    // The encrypted profile itself remains usable.
                    // A new launch will fall back to the first saved profile.
                }
            }
            message.setText("Saved VPN profile restored. Use Turn VPN On to reconnect.");
        } catch (Exception invalid) {
            selectedConfig = null;
            message.setText("Stored profile could not be parsed. No changes were made.");
        }
        refreshButtons();
    }

    private void saveSelected() {
        if (selectedConfig == null) {
            message.setText("Import or select a WireGuard configuration first.");
            return;
        }
        if (session != null && session.isConnected()) {
            message.setText("Disconnect before editing saved profiles.");
            return;
        }
        final SecureTunnelProfileStore.Profile updated;
        try {
            Config routed = VpnRouteModes.prepare(selectedConfig,
                    routingPicker.getSelectedItemPosition(), homeRoutes.getText().toString());
            VpnDnsOverride.prepare(routed, dnsOverrideEnabled(), chosenDnsAddresses());
        } catch (Exception invalid) {
            message.setText("Cannot validate routing or DNS. Check the CIDRs and DNS IPs.");
            return;
        }
        try {
            updated = new SecureTunnelProfileStore.Profile(
                    profileName.getText().toString(), selectedConfig.toWgQuickString(),
                    routingPicker.getSelectedItemPosition(), homeRoutes.getText().toString(),
                    dnsOverrideEnabled(), chosenDnsAddresses());
        } catch (IllegalArgumentException invalid) {
            message.setText(invalid.getMessage());
            return;
        }
        boolean replacing = false;
        for (SecureTunnelProfileStore.Profile profile : profiles) {
            if (profile.name.equalsIgnoreCase(updated.name)) {
                replacing = true;
                break;
            }
        }
        if (replacing) {
            new AlertDialog.Builder(this)
                    .setTitle("Replace existing encrypted VPN profile?")
                    .setMessage("This replaces the saved configuration for this name. Continue?")
                    .setNegativeButton("Cancel", null)
                    .setPositiveButton("Replace", (dialog, which) -> persist(updated))
                    .show();
        } else {
            persist(updated);
        }
    }

    private void persist(SecureTunnelProfileStore.Profile profile) {
        try {
            profileStore.save(profile);
            reloadProfiles(profile.name);
            message.setText("Encrypted VPN profile and settings saved. Use Turn VPN On to connect.");
        } catch (Exception failure) {
            message.setText("Secure storage failed. No plaintext profile was saved and existing profiles were not intentionally overwritten.");
        }
    }

    /**
     * Save connection preferences before bringing up a tunnel. If encrypted
     * storage fails, do not connect with settings Always-on cannot restore.
     * Preserve the imported WireGuard keys and the selected profile identity.
     */
    private boolean saveConnectionChoices() {
        int index = savedPicker.getSelectedItemPosition() - 1;
        if (index < 0 || index >= profiles.size()) {
            message.setText("Select a saved WireGuard profile before connecting.");
            return false;
        }
        SecureTunnelProfileStore.Profile existing = profiles.get(index);
        if (!existing.name.equals(profileName.getText().toString().trim())
                || !existing.configuration.equals(selectedConfig.toWgQuickString())) {
            message.setText("Profile name or configuration has unsaved changes. "
                    + "Use Save profile settings before connecting.");
            return false;
        }
        try {
            SecureTunnelProfileStore.Profile updated =
                    new SecureTunnelProfileStore.Profile(existing.name,
                            existing.configuration,
                            routingPicker.getSelectedItemPosition(),
                            homeRoutes.getText().toString(),
                            dnsOverrideEnabled(),
                            chosenDnsAddresses());
            profileStore.save(updated);
            profileStore.rememberSelectedIndex(index);
            profiles.set(index, updated);
            return true;
        } catch (Exception failure) {
            message.setText("Connection choices could not be saved securely. "
                    + "VPN was not started. Check your saved profile.");
            return false;
        }
    }

    private void confirmDelete() {
        int index = savedPicker.getSelectedItemPosition() - 1;
        if (index < 0 || index >= profiles.size()) {
            message.setText("Select a saved profile before deleting it.");
            return;
        }
        if (session != null && session.isConnected()) {
            message.setText("Disconnect before deleting a VPN profile.");
            return;
        }
        String name = profiles.get(index).name;
        new AlertDialog.Builder(this).setTitle("Delete encrypted VPN profile?")
                .setMessage("Remove \"" + name + "\" from this device? This cannot be undone.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Delete", (dialog, which) -> {
                    try {
                        profileStore.delete(name);
                        selectedConfig = null;
                        pendingConnection = null;
                        profileName.setText("");
                        routingPicker.setSelection(VpnRouteModes.PROFILE);
                        homeRoutes.setText("");
                        dnsPicker.setSelection(VpnDnsPresets.IMPORTED);
                        customDnsAddresses.setText("");
                        reloadProfiles(null);
                        refreshRoutingPreview();
                        message.setText("Saved profile deleted from the encrypted store.");
                        refreshButtons();
                    } catch (Exception failure) {
                        message.setText("Unable to finish deleting this profile. "
                                + "Refresh the profile list to verify what remains saved.");
                    }
                }).show();
    }

    private void reloadProfiles(String selectName) {
        try {
            List<SecureTunnelProfileStore.Profile> items = profileStore.load();
            profiles.clear();
            profiles.addAll(items);
            List<String> labels = new ArrayList<>();
            labels.add("Choose a saved profile");
            int desired = profileStore.preferredIndex(items.size()) + 1;
            for (int i = 0; i < items.size(); i++) {
                labels.add(items.get(i).name);
                if (selectName != null && items.get(i).name.equalsIgnoreCase(selectName)) {
                    desired = i + 1;
                }
            }
            updatingList = true;
            ArrayAdapter<String> adapter = new ArrayAdapter<String>(this,
                    android.R.layout.simple_spinner_item, labels) {
                @Override public View getView(int position, View convertView,
                                              android.view.ViewGroup parent) {
                    View row = super.getView(position, convertView, parent);
                    if (row instanceof TextView) ((TextView) row).setTextColor(WHITE);
                    return row;
                }
                @Override public View getDropDownView(int position, View convertView,
                                                      android.view.ViewGroup parent) {
                    View row = super.getDropDownView(position, convertView, parent);
                    if (row instanceof TextView) ((TextView) row).setTextColor(Color.BLACK);
                    return row;
                }
            };
            adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
            savedPicker.setAdapter(adapter);
            savedPicker.setSelection(desired);
            updatingList = false;
            if (desired > 0) {
                loadSelected(items.get(desired - 1));
            } else {
                selectedConfig = null;
                pendingConnection = null;
                refreshRoutingPreview();
            }
        } catch (Exception unavailable) {
            updatingList = false;
            message.setText("Encrypted profiles could not be read. Nothing was overwritten. The Android Keystore may have changed.");
        }
    }

    private void refreshRoutingPreview() {
        if (routeStatus == null || routingPicker == null || homeRoutes == null) return;
        int mode = routingPicker.getSelectedItemPosition();
        homeRoutes.setVisibility(mode == VpnRouteModes.HOME ? View.VISIBLE : View.GONE);
        routeStatus.setText(VpnRouteModes.summary(
                selectedConfig, mode, homeRoutes.getText().toString()));
        refreshDnsPreview();
    }

    private boolean dnsOverrideEnabled() {
        return VpnDnsPresets.isOverride(dnsPicker.getSelectedItemPosition());
    }

    private String chosenDnsAddresses() {
        return VpnDnsPresets.addresses(dnsPicker.getSelectedItemPosition(),
                customDnsAddresses.getText().toString());
    }

    private void refreshDnsPreview() {
        if (dnsPicker == null || customDnsAddresses == null || dnsStatus == null) return;
        int choice = dnsPicker.getSelectedItemPosition();
        customDnsAddresses.setVisibility(choice == VpnDnsPresets.CUSTOM
                ? View.VISIBLE : View.GONE);
        if (choice == VpnDnsPresets.IMPORTED) {
            boolean existingDns = VpnDnsOverride.hasDns(selectedConfig);
            if (!existingDns && routingPicker != null
                    && routingPicker.getSelectedItemPosition() == VpnRouteModes.ALL) {
                dnsStatus.setTextColor(0xffffc6b0);
                dnsStatus.setText("WARNING: No DNS configured. Websites may fail with Android VPN lockdown. Choose a preset.");
            } else {
                dnsStatus.setTextColor(MUTED);
                dnsStatus.setText(existingDns
                        ? "Using DNS already present in the imported WireGuard profile."
                        : "No DNS override. The imported profile does not provide a DNS server.");
            }
        } else {
            dnsStatus.setTextColor(MUTED);
            String configured = chosenDnsAddresses();
            dnsStatus.setText(choice == VpnDnsPresets.CUSTOM && configured.isEmpty()
                    ? "Enter a numeric DNS IP before connecting."
                    : "Selected DNS: " + configured + "\nSaved with this profile when you connect.");
        }
    }

    private void confirmConnect() {
        if (session == null || selectedConfig == null) {
            message.setText("Choose or import a VPN profile first.");
            return;
        }
        if (session.isBusy() || session.isConnected()) return;
        final int mode = routingPicker.getSelectedItemPosition();
        final Config connectionConfig;
        try {
            Config routed = VpnRouteModes.prepare(
                    selectedConfig, mode, homeRoutes.getText().toString());
            connectionConfig = VpnDnsOverride.prepare(
                    routed, dnsOverrideEnabled(), chosenDnsAddresses());
        } catch (Exception invalid) {
            // Avoid logging or echoing configuration details, including private keys.
            message.setText("Cannot apply routing or DNS. Check the peer count, CIDRs and numeric DNS IPs.");
            return;
        }
        if (mode == VpnRouteModes.ALL && !VpnDnsOverride.hasDns(connectionConfig)) {
            new AlertDialog.Builder(this)
                    .setTitle("No DNS server configured")
                    .setMessage("The WireGuard tunnel has no DNS server. Under Android "
                            + "Block connections without VPN, websites may fail to resolve. "
                            + "Choose a DNS preset or explicitly continue without DNS.")
                    .setNegativeButton("Choose DNS", null)
                    .setPositiveButton("Continue without DNS", (dialog, which) ->
                            showConnectionConfirmation(mode, connectionConfig))
                    .show();
            return;
        }
        showConnectionConfirmation(mode, connectionConfig);
    }

    private void showConnectionConfirmation(int mode, Config connectionConfig) {
        String warning = VpnRouteModes.summary(
                selectedConfig, mode, homeRoutes.getText().toString())
                + "\n\nConnecting saves these routing and DNS choices in your encrypted profile."
                + "\n\nAndroid permits only one active VPN: Tailscale may disconnect. "
                + "No fail-closed, DNS-leak or IPv6-leak protection is guaranteed.";
        if (dnsOverrideEnabled()) {
            warning += "\n\nDNS overrides must be routed through WireGuard. "
                    + "The app does not implement DoH/DoQ or provide a DNS-leak guarantee.";
        }
        if (mode == VpnRouteModes.ALL) {
            warning += "\n\nThe Fedora gateway MUST support IPv4 forwarding/NAT and IPv6 routing. "
                    + "A handshake alone cannot prove this; test internet and DNS on cellular.";
        }
        new AlertDialog.Builder(this)
                .setTitle(mode == VpnRouteModes.ALL
                        ? "Test experimental all-internet VPN?" : "Start WireGuard VPN?")
                .setMessage(warning)
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Connect", (dialog, which) -> {
                    if (!saveConnectionChoices()) return;
                    pendingConnection = connectionConfig;
                    Intent permission = VpnService.prepare(this);
                    if (permission != null) {
                        startActivityForResult(permission, VPN_PERMISSION);
                    } else {
                        startTunnel();
                    }
                }).show();
    }

    private void startTunnel() {
        if (session == null || pendingConnection == null) {
            message.setText("Connection preparation expired. Press Connect again.");
            return;
        }
        Config runtime = pendingConnection;
        pendingConnection = null;
        message.setText("Starting WireGuard. Interface UP does not prove internet privacy.");
        session.connect(runtime, (success, summary) -> {
            if (!isFinishing() && !isDestroyed()) {
                if (success) requestTrafficNotificationPermission();
                message.setText(summary);
                refreshButtons();
                pollHandler.removeCallbacks(poll);
                if (visible) pollHandler.post(poll);
            }
        });
        refreshButtons();
    }


    private void requestTrafficNotificationPermission() {
        if (Build.VERSION.SDK_INT < 33) return;
        if (checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS)
                == PackageManager.PERMISSION_GRANTED) return;
        if (getPreferences(Context.MODE_PRIVATE)
                .getBoolean("traffic_notification_permission_asked", false)) return;
        getPreferences(Context.MODE_PRIVATE).edit()
                .putBoolean("traffic_notification_permission_asked", true).apply();
        requestPermissions(new String[] {
                android.Manifest.permission.POST_NOTIFICATIONS
        }, NOTIFICATION_PERMISSION);
    }

    private void stopTunnel() {
        if (session == null || session.isBusy()) return;
        pendingConnection = null;
        message.setText("Stopping WireGuard...");
        session.disconnect((success, summary) -> {
            if (!isFinishing() && !isDestroyed()) {
                message.setText(summary);
                refreshButtons();
                if (visible) {
                    pollHandler.removeCallbacks(poll);
                    pollHandler.post(poll);
                }
            }
        });
        refreshButtons();
    }

    private void refreshButtons() {
        if (importButton == null) return;
        boolean active = session != null && session.isConnected();
        boolean busy = session != null && session.isBusy();
        boolean systemAlwaysOn = active && session.isAlwaysOn();
        vpnToggleButton.setText(systemAlwaysOn ? "VPN managed by Android Always-on"
                : active ? "Turn VPN Off" : "Turn VPN On");
        vpnToggleButton.setEnabled(!busy && !systemAlwaysOn
                && (active || selectedConfig != null));
        diagnosticsButton.setEnabled(active && !busy && !diagnosticsRunning);
        importButton.setEnabled(!active && !busy);
        saveButton.setEnabled(!active && !busy && selectedConfig != null);
        deleteButton.setEnabled(!active && !busy && !profiles.isEmpty());
        savedPicker.setEnabled(!active && !busy);
        profileName.setEnabled(!active && !busy);
        routingPicker.setEnabled(!active && !busy);
        homeRoutes.setEnabled(!active && !busy);
        dnsPicker.setEnabled(!active && !busy);
        customDnsAddresses.setEnabled(!active && !busy);
    }

    private LinearLayout card(LinearLayout parent) {
        LinearLayout child = new LinearLayout(this);
        child.setOrientation(LinearLayout.VERTICAL);
        child.setPadding(dp(16), dp(14), dp(16), dp(16));
        GradientDrawable background = new GradientDrawable();
        background.setColor(0xff292135);
        background.setCornerRadius(dp(18));
        child.setBackground(background);
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
        params.bottomMargin = dp(16);
        parent.addView(child, params);
        return child;
    }

    private TextView label(LinearLayout parent, String label, int size, int color) {
        TextView view = new TextView(this);
        view.setText(label);
        view.setTextSize(size);
        view.setTextColor(color);
        view.setPadding(0, dp(6), 0, dp(8));
        parent.addView(view);
        return view;
    }

    private Button button(LinearLayout parent, String title) {
        Button view = new Button(this);
        view.setAllCaps(false);
        view.setText(title);
        parent.addView(view);
        return view;
    }

    private int dp(int units) {
        return (int) (units * getResources().getDisplayMetrics().density);
    }
}
