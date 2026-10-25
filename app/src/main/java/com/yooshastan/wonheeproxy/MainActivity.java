package com.yooshastan.wonheeproxy;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipDescription;
import android.content.ClipboardManager;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.graphics.Color;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.Uri;
import android.os.Bundle;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.PersistableBundle;
import android.os.SystemClock;
import android.text.InputType;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;

import com.yooshastan.wonheeproxy.core.EndpointSelector;
import com.yooshastan.wonheeproxy.core.ProxyEndpoint;
import com.yooshastan.wonheeproxy.core.ProxyProbe;
import com.yooshastan.wonheeproxy.core.ProbeHistory;
import com.yooshastan.wonheeproxy.core.UltgramPackages;

import java.net.Inet4Address;
import java.util.ArrayList;
import java.util.List;

/**
 * Standalone, user-controlled Ultgram proxy companion.
 * MTProto controls are separate from the opt-in experimental VPN. Only an explicit tap sends
 * the user's proxy URL to an allowlisted Ultgram package.
 */
public final class MainActivity extends Activity {
    private static final int BG = Color.rgb(18, 16, 29);
    private static final int FOREGROUND = Color.rgb(248, 241, 249);
    private static final int PINK = Color.rgb(251, 173, 216);

    private Spinner protocol, mode, savedPicker;
    private EditText profileName, publicHost, lanHost, port, secret, username, password;
    private LinearLayout mtprotoFields, socksFields;
    private TextView status;
    private SecureProfileStore store;
    private final List<SecureProfileStore.Profile> saved = new ArrayList<>();
    private boolean rebuildingPicker;

    private static final long MONITOR_INTERVAL_MS = 15000L;
    private final Handler monitorHandler = new Handler(Looper.getMainLooper());
    private ProbeHistory monitorHistory = new ProbeHistory();
    private boolean monitorRunning;
    private boolean probeInFlight;
    private int monitorGeneration;
    private long monitorStartedMs;
    private long monitorFinishedMs;
    private Resolved monitoredEndpoint;
    private TextView monitorStatus;
    private Button startMonitorButton, stopMonitorButton;
    private final Runnable scheduledProbe = this::runNextMonitorProbe;

    private static final class Resolved {
        final ProxyEndpoint endpoint;
        final EndpointSelector.Selection selection;

        Resolved(ProxyEndpoint endpoint, EndpointSelector.Selection selection) {
            this.endpoint = endpoint;
            this.selection = selection;
        }
    }

    @Override
    protected void onCreate(Bundle savedState) {
        super.onCreate(savedState);
        store = new SecureProfileStore(this);

        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(BG);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(22), dp(26), dp(22), dp(30));
        scroll.addView(root);
        setContentView(scroll);

        root.addView(text("WONHEE PROXY", 28, PINK));
        root.addView(text("Privacy gateway companion · Alpha 0.4", 15, FOREGROUND));
        root.addView(space(16));
        root.addView(text("Save encrypted proxy profiles, choose a home LAN or public endpoint, "
                + "and send a proxy link to Ultgram when you tap Import. "
                + "Wonhee changes Ultgram only when you tap Import. VPN mode is a separate, explicit action.",
                15, FOREGROUND));
        root.addView(space(16));

        root.addView(text("Saved profiles", 16, PINK));
        savedPicker = spinner(root, new String[]{"New / unsaved"});
        savedPicker.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                if (!rebuildingPicker && position > 0 && position <= saved.size()) {
                    applyProfile(saved.get(position - 1));
                }
            }
            @Override public void onNothingSelected(AdapterView<?> parent) { }
        });

        profileName = field(root, "Profile name", "e.g. Home MTProxy", false, false);
        root.addView(text("Protocol", 16, PINK));
        protocol = spinner(root, new String[]{"MTProto", "SOCKS5"});
        protocol.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> parent, View view, int index, long id) {
                if (mtprotoFields != null) mtprotoFields.setVisibility(index == 0 ? View.VISIBLE : View.GONE);
                if (socksFields != null) socksFields.setVisibility(index == 1 ? View.VISIBLE : View.GONE);
            }
            @Override public void onNothingSelected(AdapterView<?> parent) { }
        });

        publicHost = field(root, "Public server IP or DNS name",
                "Your public IP or a DNS hostname", false, false);
        lanHost = field(root, "Optional home LAN IPv4 address",
                "192.168.1.10", false, false);
        port = field(root, "TCP port", "8443", false, true);
        port.setText("8443");

        root.addView(text("Endpoint choice", 16, PINK));
        mode = spinner(root, new String[]{
                "Auto: same Wi-Fi subnet → LAN",
                "Public endpoint",
                "LAN endpoint (manual)"
        });
        root.addView(text("Auto uses the LAN address only when its private IPv4 range matches "
                + "the active Wi-Fi network without a VPN. Otherwise it selects public. "
                + "A matching subnet is not proof that you are at home: verify the address before importing.",
                12, FOREGROUND));

        mtprotoFields = new LinearLayout(this);
        mtprotoFields.setOrientation(LinearLayout.VERTICAL);
        root.addView(mtprotoFields);
        secret = field(mtprotoFields, "MTProto secret", "Secret (hex)", true, false);

        socksFields = new LinearLayout(this);
        socksFields.setOrientation(LinearLayout.VERTICAL);
        root.addView(socksFields);
        username = field(socksFields, "SOCKS5 username (optional)", "Username", false, false);
        password = field(socksFields, "SOCKS5 password (optional)", "Password", true, false);
        socksFields.setVisibility(View.GONE);

        root.addView(space(12));
        Button saveButton = button(root, "Save / update encrypted profile");
        saveButton.setOnClickListener(v -> saveCurrentProfile());
        Button deleteButton = button(root, "Delete selected profile");
        deleteButton.setOnClickListener(v -> confirmDelete());

        root.addView(space(12));
        Button testButton = button(root, "Test selected TCP endpoint");
        testButton.setOnClickListener(v -> confirmTcpTest());
        Button importButton = button(root, "Open in Ultgram");
        importButton.setOnClickListener(v -> openInUltgram());

        root.addView(space(16));
        root.addView(text("Experimental VPN · Alpha 0.4", 16, PINK));
        root.addView(text("Import a private WireGuard configuration and explicitly request "
                + "Android VPN permission. This can replace Tailscale; no DNS filtering, "
                + "kill switch or leak protection is present yet.", 13, FOREGROUND));
        Button vpnButton = button(root, "Open WireGuard VPN (experimental)");
        vpnButton.setOnClickListener(v -> startActivity(
                new Intent(this, VpnActivity.class)));

        root.addView(space(16));
        root.addView(text("Opt-in TCP monitor", 16, PINK));
        root.addView(text("Checks the selected endpoint about every 15 seconds while "
                + "this screen stays visible. Stops when you leave Wonhee. "
                + "These checks measure TCP reachability, not Telegram routing or server uptime.",
                13, FOREGROUND));
        startMonitorButton = button(root, "Start foreground TCP monitor");
        startMonitorButton.setOnClickListener(v -> confirmStartMonitor());
        stopMonitorButton = button(root, "Stop monitor");
        stopMonitorButton.setOnClickListener(v -> stopMonitor("Monitor stopped."));
        stopMonitorButton.setEnabled(false);
        Button copyReportButton = button(root, "Copy redacted TCP diagnostic report");
        copyReportButton.setOnClickListener(v -> copyRedactedDiagnostics());
        monitorStatus = text("Monitor is off. No checks have been run.", 13, FOREGROUND);
        root.addView(monitorStatus);

        status = text("Ready. TCP checks never authenticate an MTProto or SOCKS5 connection.",
                14, FOREGROUND);
        root.addView(space(12));
        root.addView(status);
        root.addView(space(16));
        root.addView(text("Security: profiles are saved only when you choose Save and are "
                + "encrypted with Android Keystore (AES-GCM). No cloud backup. "
                + "A remote proxy may conceal your phone's IP from Telegram, but its operator "
                + "can see your IP. Your Telegram account identity remains unchanged. "
                + "No DNS ad blocking, strict routing or Navidrome access in this alpha.",
                13, FOREGROUND));

        refreshSavedProfiles(null);
    }

    private Spinner spinner(LinearLayout parent, String[] items) {
        Spinner view = new Spinner(this);
        view.setAdapter(new ArrayAdapter<String>(this,
                android.R.layout.simple_spinner_item, items) {
            @Override public View getView(int position, View convertView,
                                           android.view.ViewGroup group) {
                View result = super.getView(position, convertView, group);
                if (result instanceof TextView) ((TextView) result).setTextColor(FOREGROUND);
                return result;
            }
            @Override public View getDropDownView(int position, View convertView,
                                                   android.view.ViewGroup group) {
                View result = super.getDropDownView(position, convertView, group);
                if (result instanceof TextView) ((TextView) result).setTextColor(Color.BLACK);
                return result;
            }
        });
        parent.addView(view);
        return view;
    }

    private SecureProfileStore.Profile captureInputs(boolean requireName) {
        int selectedPort;
        try {
            selectedPort = Integer.parseInt(port.getText().toString().trim());
        } catch (NumberFormatException invalid) {
            throw new IllegalArgumentException("Enter a TCP port from 1 to 65535.");
        }
        String name = profileName.getText().toString().trim();
        if (name.isEmpty() && !requireName) name = "Unsaved";
        SecureProfileStore.Profile profile = new SecureProfileStore.Profile(
                name,
                protocol.getSelectedItemPosition() == 0 ? "MTProto" : "SOCKS5",
                EndpointSelector.Mode.values()[mode.getSelectedItemPosition()].name(),
                publicHost.getText().toString(), lanHost.getText().toString(),
                selectedPort, secret.getText().toString(), username.getText().toString(),
                password.getText().toString());
        // Validate both hosts with the same secret and protocol. No network request.
        endpointFor(profile, profile.publicHost);
        if (!profile.lanHost.isEmpty()) endpointFor(profile, profile.lanHost);
        return profile;
    }

    private static ProxyEndpoint endpointFor(SecureProfileStore.Profile profile, String host) {
        if ("MTProto".equals(profile.protocol)) {
            return ProxyEndpoint.mtproto(host, profile.port, profile.secret);
        }
        return ProxyEndpoint.socks5(host, profile.port, profile.username, profile.password);
    }

    private Resolved resolveCurrent() {
        SecureProfileStore.Profile profile = captureInputs(false);
        EndpointSelector.Mode preference = EndpointSelector.Mode.valueOf(profile.mode);
        boolean onLan = sameWifiSubnet(profile.lanHost);
        EndpointSelector.Selection chosen = EndpointSelector.select(
                profile.publicHost, profile.lanHost, preference, onLan);
        return new Resolved(endpointFor(profile, chosen.host), chosen);
    }

    /** A same-subnet route is only a selection hint, never proof of home identity. */
    private boolean sameWifiSubnet(String target) {
        if (target == null || target.isEmpty()) return false;
        ConnectivityManager manager =
                (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
        if (manager == null) return false;
        try {
            Network network = manager.getActiveNetwork();
            if (network == null) return false;
            NetworkCapabilities caps = manager.getNetworkCapabilities(network);
            if (caps == null || !caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                    || caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                return false;
            }
            LinkProperties links = manager.getLinkProperties(network);
            if (links == null) return false;
            for (LinkAddress address : links.getLinkAddresses()) {
                if (address.getAddress() instanceof Inet4Address
                        && EndpointSelector.samePrivateSubnet(
                                address.getAddress().getHostAddress(),
                                address.getPrefixLength(), target)) {
                    return true;
                }
            }
        } catch (SecurityException denied) {
            // No location permission requested; choose the public endpoint.
        }
        return false;
    }

    private void saveCurrentProfile() {
        try {
            SecureProfileStore.Profile profile = captureInputs(true);
            // Ensure that the chosen mode is also valid, e.g. LAN requires an address.
            EndpointSelector.select(profile.publicHost, profile.lanHost,
                    EndpointSelector.Mode.valueOf(profile.mode), false);
            store.save(profile);
            refreshSavedProfiles(profile.name);
            status.setText("Profile saved with Android Keystore encryption. "
                    + "It is not automatically enabled in Ultgram.");
        } catch (IllegalArgumentException invalid) {
            status.setText(invalid.getMessage());
        } catch (Exception unavailable) {
            status.setText("Secure storage unavailable. No plaintext profile was saved. "
                    + "Check device Keystore availability.");
        }
    }

    private void refreshSavedProfiles(String selectName) {
        try {
            List<SecureProfileStore.Profile> loaded = store.load();
            saved.clear();
            saved.addAll(loaded);
            List<String> labels = new ArrayList<>();
            labels.add("New / unsaved");
            int selected = 0;
            for (int i = 0; i < loaded.size(); i++) {
                labels.add(loaded.get(i).name);
                if (selectName != null && loaded.get(i).name.equalsIgnoreCase(selectName)) {
                    selected = i + 1;
                }
            }
            rebuildingPicker = true;
            ArrayAdapter<String> adapter = new ArrayAdapter<String>(this,
                    android.R.layout.simple_spinner_item, labels) {
                @Override public View getView(int position, View convertView,
                                               android.view.ViewGroup parent) {
                    View item = super.getView(position, convertView, parent);
                    if (item instanceof TextView) ((TextView) item).setTextColor(FOREGROUND);
                    return item;
                }
                @Override public View getDropDownView(int position, View convertView,
                                                       android.view.ViewGroup parent) {
                    View item = super.getDropDownView(position, convertView, parent);
                    if (item instanceof TextView) ((TextView) item).setTextColor(Color.BLACK);
                    return item;
                }
            };
            adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
            savedPicker.setAdapter(adapter);
            savedPicker.setSelection(selected);
            rebuildingPicker = false;
        } catch (Exception unavailable) {
            rebuildingPicker = false;
            status.setText("Saved profiles could not be decrypted. "
                    + "Nothing was overwritten; device Keystore may have changed.");
        }
    }

    private void applyProfile(SecureProfileStore.Profile profile) {
        profileName.setText(profile.name);
        protocol.setSelection("MTProto".equals(profile.protocol) ? 0 : 1);
        mode.setSelection(EndpointSelector.Mode.valueOf(profile.mode).ordinal());
        publicHost.setText(profile.publicHost);
        lanHost.setText(profile.lanHost);
        port.setText(Integer.toString(profile.port));
        secret.setText(profile.secret);
        username.setText(profile.username);
        password.setText(profile.password);
        status.setText("Loaded encrypted profile \"" + profile.name + "\". "
                + "Check the selected host before testing or importing.");
    }

    private void confirmDelete() {
        int selected = savedPicker.getSelectedItemPosition() - 1;
        if (selected < 0 || selected >= saved.size()) {
            status.setText("Select a saved profile to delete.");
            return;
        }
        String name = saved.get(selected).name;
        new AlertDialog.Builder(this)
                .setTitle("Delete saved profile?")
                .setMessage("Remove \"" + name + "\" from Wonhee Proxy? "
                        + "This will not remove an already imported proxy from Ultgram.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Delete", (dialog, which) -> {
                    try {
                        store.delete(name);
                        refreshSavedProfiles(null);
                        status.setText("Saved profile removed from Wonhee Proxy.");
                    } catch (Exception unavailable) {
                        status.setText("Could not delete profile. Secure storage is unchanged.");
                    }
                }).show();
    }

    private void confirmTcpTest() {
        final Resolved chosen;
        try {
            chosen = resolveCurrent();
        } catch (IllegalArgumentException invalid) {
            status.setText(invalid.getMessage());
            return;
        }
        String location = chosen.selection.local ? "LAN" : "public";
        new AlertDialog.Builder(this)
                .setTitle("Direct TCP reachability test")
                .setMessage("Test " + chosen.endpoint.host + ":" + chosen.endpoint.port
                        + " (" + location + ")? The server may see your IP. "
                        + "This only opens a TCP socket. It does not authenticate an MTProto "
                        + "or SOCKS5 proxy, verify routing, or prove anonymity.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Run test", (dialog, selected) -> {
                    status.setText("Checking " + chosen.endpoint.safeDescription()
                            + " · " + chosen.selection.reason + "…");
                    new Thread(() -> {
                        ProxyProbe.Result result = ProxyProbe.check(chosen.endpoint, 4000);
                        runOnUiThread(() -> {
                            if (!isFinishing() && !isDestroyed()) {
                                status.setText(result.safeSummary() + " "
                                        + chosen.selection.reason + " — "
                                        + "TCP only; MTProto/SOCKS5 authentication not tested.");
                            }
                        });
                    }, "WonheeProxyTcpTest").start();
                }).show();
    }

    private void openInUltgram() {
        final Resolved chosen;
        try {
            chosen = resolveCurrent();
        } catch (IllegalArgumentException invalid) {
            status.setText(invalid.getMessage());
            return;
        }
        // Every attempted destination is a first-party package; never show an
        // unscoped chooser containing a credential-bearing tg:// URL.
        Uri deepLink = Uri.parse(chosen.endpoint.telegramDeepLink());
        for (String packageName : UltgramPackages.candidates()) {
            Intent intent = new Intent(Intent.ACTION_VIEW, deepLink);
            intent.addCategory(Intent.CATEGORY_BROWSABLE);
            intent.setPackage(packageName);
            try {
                startActivity(intent);
                status.setText("Sent " + chosen.endpoint.safeDescription() + " to Ultgram. "
                        + chosen.selection.reason + ". Confirm and enable the proxy in Ultgram. "
                        + "No authenticated proxy handshake was tested here.");
                return;
            } catch (ActivityNotFoundException ignored) {
                // Other known Ultgram variants only.
            }
        }
        status.setText("No compatible Ultgram build accepted the proxy link. "
                + "Check the installed Ultgram APK/package.");
    }

    @Override
    protected void onStop() {
        stopMonitor("Monitor stopped as Wonhee left the foreground.");
        super.onStop();
    }

    private void confirmStartMonitor() {
        if (monitorRunning) return;
        final Resolved chosen;
        try {
            chosen = resolveCurrent();
        } catch (IllegalArgumentException invalid) {
            status.setText(invalid.getMessage());
            return;
        }
        new AlertDialog.Builder(this)
                .setTitle("Start foreground TCP monitoring?")
                .setMessage("Every ~15 seconds while Wonhee is visible, connect to "
                        + chosen.endpoint.host + ":" + chosen.endpoint.port + " ("
                        + chosen.selection.reason + "). Your server can see "
                        + "your IP and repeated connection attempts. This is a TCP-only "
                        + "monitor; it does not authenticate MTProto, measure Telegram "
                        + "traffic, prove privacy, or run in the background.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Start", (dialog, which) -> {
                    monitorHistory = new ProbeHistory();
                    monitoredEndpoint = chosen;
                    monitorStartedMs = SystemClock.elapsedRealtime();
                    monitorFinishedMs = 0;
                    monitorRunning = true;
                    probeInFlight = false;
                    monitorGeneration++;
                    startMonitorButton.setEnabled(false);
                    stopMonitorButton.setEnabled(true);
                    monitorStatus.setText("Starting TCP checks for "
                            + chosen.endpoint.safeDescription() + ". "
                            + "The endpoint is pinned until the monitor stops.");
                    monitorHandler.post(scheduledProbe);
                }).show();
    }

    private void runNextMonitorProbe() {
        if (!monitorRunning || probeInFlight || monitoredEndpoint == null) return;
        probeInFlight = true;
        final int generation = monitorGeneration;
        final ProxyEndpoint endpoint = monitoredEndpoint.endpoint;
        new Thread(() -> {
            ProxyProbe.Result result = ProxyProbe.check(endpoint, 4000);
            runOnUiThread(() -> {
                if (generation != monitorGeneration || !monitorRunning
                        || isFinishing() || isDestroyed()) return;
                probeInFlight = false;
                monitorHistory.record(result.status, result.elapsedMillis);
                monitorStatus.setText(monitorHistory.shortSummary()
                        + "\nObservation time: " + (monitorDurationMs() / 1000)
                        + " s. TCP only; no proxy handshake verified.");
                monitorHandler.postDelayed(scheduledProbe, MONITOR_INTERVAL_MS);
            });
        }, "WonheeForegroundTcpMonitor").start();
    }

    private long monitorDurationMs() {
        if (monitorStartedMs == 0) return 0;
        long end = monitorRunning ? SystemClock.elapsedRealtime() : monitorFinishedMs;
        return Math.max(0L, end - monitorStartedMs);
    }

    private void stopMonitor(String message) {
        if (!monitorRunning) return;
        monitorFinishedMs = SystemClock.elapsedRealtime();
        monitorRunning = false;
        monitorGeneration++;
        probeInFlight = false;
        monitoredEndpoint = null;
        monitorHandler.removeCallbacks(scheduledProbe);
        if (startMonitorButton != null) startMonitorButton.setEnabled(true);
        if (stopMonitorButton != null) stopMonitorButton.setEnabled(false);
        if (monitorStatus != null) {
            monitorStatus.setText(message + " " + monitorHistory.shortSummary()
                    + "\nObservation time: " + (monitorDurationMs() / 1000) + " s.");
        }
    }

    private void copyRedactedDiagnostics() {
        // ProbeHistory records only status and elapsed milliseconds: never
        // the server hostname, IP address, secret or SOCKS5 credentials.
        String report = monitorHistory.redactedSnapshot(monitorRunning,
                monitorDurationMs());
        ClipboardManager manager =
                (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
        if (manager == null) {
            status.setText("Clipboard is unavailable.");
            return;
        }
        ClipData clip = ClipData.newPlainText("Wonhee redacted TCP diagnostics", report);
        if (Build.VERSION.SDK_INT >= 33) {
            PersistableBundle extras = new PersistableBundle();
            extras.putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true);
            clip.getDescription().setExtras(extras);
        }
        manager.setPrimaryClip(clip);
        status.setText("Redacted TCP stats copied. No hostname, IP or proxy "
                + "credential was included. Clipboard contents can still be read "
                + "by other apps with clipboard access.");
    }

    private TextView text(String value, int sp, int color) {
        TextView label = new TextView(this);
        label.setText(value);
        label.setTextSize(sp);
        label.setTextColor(color);
        label.setPadding(0, dp(4), 0, dp(6));
        return label;
    }

    private EditText field(LinearLayout parent, String label, String hint,
                           boolean hidden, boolean numeric) {
        parent.addView(text(label, 14, PINK));
        EditText input = new EditText(this);
        input.setTextColor(FOREGROUND);
        input.setHintTextColor(Color.rgb(170, 161, 182));
        input.setHint(hint);
        input.setSingleLine(true);
        if (numeric) {
            input.setInputType(InputType.TYPE_CLASS_NUMBER);
        } else if (hidden) {
            input.setInputType(InputType.TYPE_CLASS_TEXT
                    | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        } else {
            input.setInputType(InputType.TYPE_CLASS_TEXT);
        }
        parent.addView(input);
        return input;
    }

    private Button button(LinearLayout parent, String label) {
        Button button = new Button(this);
        button.setText(label);
        parent.addView(button);
        return button;
    }

    private View space(int height) {
        View spacer = new View(this);
        spacer.setLayoutParams(new LinearLayout.LayoutParams(1, dp(height)));
        return spacer;
    }

    private int dp(int amount) {
        return Math.round(getResources().getDisplayMetrics().density * amount);
    }
}
