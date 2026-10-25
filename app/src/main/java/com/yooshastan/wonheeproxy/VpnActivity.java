package com.yooshastan.wonheeproxy;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
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
 * Alpha 0.6: VPN-first screen with encrypted profiles, connect-time routing
 * choices and native WireGuard diagnostics. No automatic startup or fail-closed
 * protection is claimed. Telegram proxy tools remain in MainActivity.
 */
public final class VpnActivity extends Activity {
    private static final int PICK_CONFIG = 4201;
    private static final int VPN_PERMISSION = 4202;
    private static final int PINK = 0xfffbadd8;
    private static final int WHITE = 0xfff8f1f9;
    private static final int MUTED = 0xffc4b7c9;
    private static final long POLL_INTERVAL_MS = 5000L;
    private final Handler pollHandler = new Handler(Looper.getMainLooper());
    private final List<SecureTunnelProfileStore.Profile> profiles = new ArrayList<>();
    private WireGuardSession session;
    private SecureTunnelProfileStore profileStore;
    private Config selectedConfig;
    private Config pendingConnection;
    private boolean updatingList;
    private boolean visible;
    private boolean statisticsPending;
    private Spinner savedPicker;
    private Spinner routingPicker;
    private EditText homeRoutes;
    private EditText profileName;
    private TextView connectionStatus;
    private TextView message;
    private TextView routeStatus;
    private TextView statisticsText;
    private Button connectButton, disconnectButton, importButton, saveButton, deleteButton;

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
        label(root, "WireGuard VPN · Alpha 0.6", 15, MUTED);

        LinearLayout dashboard = card(root);
        connectionStatus = label(dashboard, "Disconnected", 22, WHITE);
        statisticsText = label(dashboard, "No tunnel active.", 14, MUTED);
        connectButton = button(dashboard, "Connect VPN");
        connectButton.setOnClickListener(v -> confirmConnect());
        disconnectButton = button(dashboard, "Disconnect VPN");
        disconnectButton.setOnClickListener(v -> stopTunnel());
        label(dashboard, "VPN interface and handshake are different states. A handshake does not prove DNS or full-device leak protection.", 12, MUTED);

        LinearLayout configCard = card(root);
        label(configCard, "WIREGUARD PROFILES", 17, PINK);
        savedPicker = new Spinner(this);
        configCard.addView(savedPicker);
        savedPicker.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                if (!updatingList && position > 0 && position <= profiles.size()) {
                    loadSelected(profiles.get(position - 1));
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
        saveButton = button(configCard, "Save encrypted profile");
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
        label(routingCard, "Routes apply to this connection only. Press Save encrypted profile "
                + "to remember your mode and home CIDRs. Neither changes the original WireGuard keys.", 12, MUTED);

        message = label(root, "VPN is off. A saved profile connects only when you press Connect.", 14, WHITE);
        Button proxyTools = button(root, "Telegram proxy tools");
        proxyTools.setOnClickListener(v -> startActivity(new Intent(this, MainActivity.class)));
        label(root, "Security: VPN profiles are encrypted at rest with Android Keystore and are never uploaded or logged. Your keys are saved only when you press Save. Back them up privately before uninstalling or replacing a debug APK.", 12, MUTED);
        label(root, "Still experimental: no Always-on, automatic restart, kill switch, encrypted DNS enforcement or tracker filtering. All internet mode depends on a working home gateway and has no verified leak protection. Starting this VPN replaces any active Tailscale or other Android VPN.", 12, MUTED);

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
        pollHandler.removeCallbacks(poll);
        pollHandler.post(poll);
    }

    @Override protected void onPause() {
        visible = false;
        pollHandler.removeCallbacks(poll);
        super.onPause();
    }

    private void renderStatistics(WireGuardSession.StatusSnapshot snapshot) {
        if (!snapshot.interfaceUp) {
            connectionStatus.setText("Disconnected");
            connectionStatus.setTextColor(WHITE);
            statisticsText.setText("No tunnel active.");
            return;
        }
        if (!snapshot.statisticsAvailable) {
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
                if (profileName.getText().toString().trim().isEmpty()) {
                    profileName.setText("Home WireGuard");
                }
                message.setText("Configuration imported into memory. Tap Save to encrypt it on this device.");
                refreshRoutingPreview();
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
        if (session != null && session.isConnected()) {
            message.setText("Disconnect before switching VPN profiles.");
            return;
        }
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
            refreshRoutingPreview();
            message.setText("Encrypted VPN profile loaded. Press Connect to start it.");
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
            VpnRouteModes.prepare(selectedConfig, routingPicker.getSelectedItemPosition(),
                    homeRoutes.getText().toString());
        } catch (Exception invalid) {
            message.setText("Cannot validate routing. Check the CIDRs (1–16, no /0 in Home mode).");
            return;
        }
        try {
            updated = new SecureTunnelProfileStore.Profile(
                    profileName.getText().toString(), selectedConfig.toWgQuickString(),
                    routingPicker.getSelectedItemPosition(), homeRoutes.getText().toString());
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
            message.setText("Encrypted profile saved locally. Connect remains manual.");
        } catch (Exception failure) {
            message.setText("Secure storage failed. No plaintext profile was saved and existing profiles were not intentionally overwritten.");
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
                        reloadProfiles(null);
                        refreshRoutingPreview();
                        message.setText("Saved profile deleted from the encrypted store.");
                        refreshButtons();
                    } catch (Exception failure) {
                        message.setText("Could not delete profile; encrypted storage was not intentionally altered.");
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
            int desired = 0;
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
            connectionConfig = VpnRouteModes.prepare(
                    selectedConfig, mode, homeRoutes.getText().toString());
        } catch (Exception invalid) {
            // Avoid logging or echoing configuration details, including private keys.
            message.setText("Cannot apply routing. Check the selected mode, peer count and home CIDRs.");
            return;
        }
        String warning = VpnRouteModes.summary(
                selectedConfig, mode, homeRoutes.getText().toString())
                + "\n\nAndroid permits only one active VPN: Tailscale may disconnect. "
                + "No fail-closed, DNS-leak or IPv6-leak protection is guaranteed.";
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
                message.setText(summary);
                refreshButtons();
                pollHandler.removeCallbacks(poll);
                if (visible) pollHandler.post(poll);
            }
        });
        refreshButtons();
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
        connectButton.setVisibility(active ? View.GONE : View.VISIBLE);
        disconnectButton.setVisibility(active ? View.VISIBLE : View.GONE);
        connectButton.setEnabled(!active && !busy && selectedConfig != null);
        disconnectButton.setEnabled(active && !busy);
        importButton.setEnabled(!active && !busy);
        saveButton.setEnabled(!active && !busy && selectedConfig != null);
        deleteButton.setEnabled(!active && !busy && !profiles.isEmpty());
        savedPicker.setEnabled(!active && !busy);
        profileName.setEnabled(!active && !busy);
        routingPicker.setEnabled(!active && !busy);
        homeRoutes.setEnabled(!active && !busy);
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
