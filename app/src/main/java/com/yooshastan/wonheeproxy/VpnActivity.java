package com.yooshastan.wonheeproxy;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.graphics.Color;
import android.net.VpnService;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import com.wireguard.config.Config;
import com.wireguard.config.InetNetwork;
import com.wireguard.config.Peer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

/**
 * Alpha 0.4 WireGuard bring-up screen. Deliberately isolated from MTProto
 * profiles: an MTProto secret must never be treated as a WireGuard key.
 */
public final class VpnActivity extends Activity {
    private static final int PICK_CONFIG = 4201;
    private static final int VPN_PERMISSION = 4202;
    private static final int MAX_CONFIG_BYTES = 65536;
    private Config selectedConfig; // Memory-only; never saved or uploaded.
    private WireGuardSession session;
    private TextView status;
    private Button importButton, connectButton, disconnectButton;

    @Override protected void onCreate(Bundle savedState) {
        super.onCreate(savedState);
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(Color.rgb(18, 16, 29));
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (22 * getResources().getDisplayMetrics().density);
        root.setPadding(pad, pad, pad, pad);
        scroll.addView(root);
        setContentView(scroll);

        label(root, "WONHEE VPN · ALPHA 0.4", 24, 0xfffbadd8);
        label(root, "Experimental WireGuard connection to a gateway you control. "
                + "This is not MTProto and does not use your Telegram proxy's secret.",
                15, 0xfff8f1f9);
        label(root, "WARNING: Starting will replace the current Android VPN, including "
                + "Tailscale. Neither a kill switch, encrypted DNS enforcement, "
                + "tracker filtering, automatic reconnection nor VPN-at-boot is "
                + "implemented. Do not use this alpha as leak protection.",
                14, 0xffffc6b0);

        importButton = button(root, "Import private WireGuard .conf (session only)");
        importButton.setOnClickListener(v -> chooseConfig());
        connectButton = button(root, "Start experimental WireGuard VPN");
        connectButton.setOnClickListener(v -> confirmVpn());
        disconnectButton = button(root, "Stop WireGuard VPN");
        disconnectButton.setOnClickListener(v -> disconnect());
        status = label(root, "No WireGuard configuration imported. VPN is off by default.",
                14, 0xfff8f1f9);
        label(root, "Alpha 0.4 routes are taken from the imported [Peer] AllowedIPs: "
                + "0.0.0.0/0 and ::/0 request full-tunnel routing; home subnets "
                + "request split routing. Split-mode DNS filtering is NOT implemented. "
                + "No WireGuard keys or .conf contents are saved by Wonhee.",
                13, 0xfff8f1f9);
        label(root, "Until we configure and verify a separate WireGuard gateway on Fedora, "
                + "a VPN interface starting does not mean internet or Navidrome works. "
                + "Keep your existing MTProxy and Tailscale available.",
                13, 0xfff8f1f9);
        try {
            session = WireGuardSession.get(this);
        } catch (RuntimeException | LinkageError failure) {
            status.setText("WireGuard engine unavailable on this device. VPN cannot start.");
        }
        refresh();
    }

    @Override protected void onResume() {
        super.onResume();
        refresh();
    }

    private void chooseConfig() {
        if (session != null && session.isConnected()) {
            status.setText("Stop the VPN before importing a different configuration.");
            return;
        }
        Intent picker = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        picker.addCategory(Intent.CATEGORY_OPENABLE);
        picker.setType("*/*");
        startActivityForResult(picker, PICK_CONFIG);
    }

    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == PICK_CONFIG) {
            if (resultCode != RESULT_OK || data == null || data.getData() == null) return;
            selectedConfig = null;
            try {
                Config parsed = loadPrivateConfig(data.getData());
                if (parsed.getPeers().isEmpty() || parsed.getInterface().getAddresses().isEmpty()) {
                    status.setText("Invalid WireGuard configuration: peer/address missing.");
                } else {
                    selectedConfig = parsed;
                    status.setText("Private WireGuard configuration imported into memory. "
                            + routeSummary(parsed) + " No connection has been started.");
                }
            } catch (Exception | LinkageError ignored) {
                status.setText("Could not parse this WireGuard .conf. "
                        + "Its contents and detailed errors are never displayed or logged.");
            }
            refresh();
        } else if (requestCode == VPN_PERMISSION) {
            if (resultCode == RESULT_OK && VpnService.prepare(this) == null) {
                connect();
            } else {
                status.setText("VPN permission not granted. Existing connections unchanged.");
            }
        }
    }

    private Config loadPrivateConfig(Uri uri) throws Exception {
        try (InputStream input = getContentResolver().openInputStream(uri)) {
            if (input == null) throw new IOException("Missing document");
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] chunk = new byte[4096];
            int bytes;
            while ((bytes = input.read(chunk)) != -1) {
                if (output.size() + bytes > MAX_CONFIG_BYTES) {
                    throw new IOException("File too large");
                }
                output.write(chunk, 0, bytes);
            }
            Arrays.fill(chunk, (byte) 0);
            byte[] data = output.toByteArray();
            try {
                return Config.parse(new ByteArrayInputStream(data));
            } finally {
                Arrays.fill(data, (byte) 0);
            }
        }
    }

    private String routeSummary(Config config) {
        boolean v4 = false;
        boolean v6 = false;
        for (Peer peer : config.getPeers()) {
            for (InetNetwork route : peer.getAllowedIps()) {
                if ("0.0.0.0/0".equals(route.toString())) v4 = true;
                if ("::/0".equals(route.toString())
                        || "0:0:0:0:0:0:0:0/0".equals(route.toString())) v6 = true;
            }
        }
        if (v4 && v6) return "Requests IPv4 and IPv6 full-tunnel routes.";
        if (v4 || v6) return "WARNING: Default route is set for only one IP family; "
                + "the other family may bypass the tunnel.";
        return "Requests split routes (not yet a protected DNS/full-device mode).";
    }

    private void confirmVpn() {
        if (selectedConfig == null || session == null) {
            status.setText("Import a private WireGuard configuration first.");
            return;
        }
        if (session.isBusy() || session.isConnected()) return;
        new AlertDialog.Builder(this)
                .setTitle("Start experimental full-device VPN?")
                .setMessage("This can disconnect Tailscale or another active VPN and "
                        + "interrupt every application's internet access. "
                        + "The gateway must support your configuration. "
                        + "No kill switch, DoQ/DoH, tracker protection, or leak guarantee exists. "
                        + "Continue only on a device where losing connectivity is acceptable.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Continue", (dialog, which) -> {
                    Intent permission = VpnService.prepare(this);
                    if (permission != null) {
                        startActivityForResult(permission, VPN_PERMISSION);
                    } else {
                        connect();
                    }
                }).show();
    }

    private void connect() {
        if (session == null || selectedConfig == null) return;
        status.setText("Requesting WireGuard tunnel; no handshake verified yet...");
        connectButton.setEnabled(false);
        session.connect(selectedConfig, (ok, message) -> {
            if (!isDestroyed()) {
                status.setText(message);
                refresh();
            }
        });
        refresh();
    }

    private void disconnect() {
        if (session == null || session.isBusy()) return;
        status.setText("Stopping experimental WireGuard...");
        session.disconnect((ok, message) -> {
            if (!isDestroyed()) {
                status.setText(message);
                refresh();
            }
        });
        refresh();
    }

    private void refresh() {
        if (importButton == null) return;
        boolean connected = session != null && session.isConnected();
        boolean busy = session != null && session.isBusy();
        importButton.setEnabled(!connected && !busy);
        connectButton.setEnabled(!connected && !busy
                && selectedConfig != null && session != null);
        disconnectButton.setEnabled(connected && !busy);
    }

    private TextView label(LinearLayout parent, String value, int size, int color) {
        TextView text = new TextView(this);
        text.setText(value);
        text.setTextSize(size);
        text.setTextColor(color);
        text.setPadding(0, 12, 0, 14);
        parent.addView(text);
        return text;
    }

    private Button button(LinearLayout parent, String value) {
        Button button = new Button(this);
        button.setText(value);
        button.setAllCaps(false);
        parent.addView(button);
        return button;
    }
}
