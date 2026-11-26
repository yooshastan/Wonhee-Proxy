package com.yooshastan.wonheeproxy;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

/** Device-side proof of JNI -> VpnService.protect() for two inactive peers. */
public final class RootlessNativeTransportActivity extends Activity {
    private static final int REQUEST_VPN = 7902;
    private static final String PREFS = "wonhee_native_transport_smoke_v1";
    private TextView status;

    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (getResources().getDisplayMetrics().density * 18);
        root.setPadding(pad, pad, pad, pad);

        TextView heading = new TextView(this);
        heading.setText("Native rootless transport · socket test");
        heading.setTextSize(21);
        root.addView(heading);

        TextView explanation = new TextView(this);
        explanation.setText(
                "This debug-only test starts two independent wireguard-go crypto devices "
                + "with temporary test keys and no peer endpoints. It verifies Android "
                + "VpnService.protect() on each IPv4 and IPv6 UDP socket. The test TUN has "
                + "NO routes, so no phone app traffic is captured or routed. No user "
                + "WireGuard profiles, DNS, Moka traffic or production settings are used.\n\n"
                + "Disconnect the official Wonhee VPN and any other VPN first. "
                + "Android Private DNS must remain OFF.");
        explanation.setTextSize(14);
        root.addView(explanation);

        status = new TextView(this);
        status.setTextSize(15);
        status.setPadding(0, pad, 0, pad);
        root.addView(status, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        Button start = new Button(this);
        start.setText("Run protected socket test");
        start.setOnClickListener(v -> requestAndStart());
        root.addView(start);

        Button stop = new Button(this);
        stop.setText("Stop test and release sockets");
        stop.setOnClickListener(v -> {
            Intent intent = new Intent(this, RootlessNativeTransportService.class)
                    .setAction(RootlessNativeTransportService.ACTION_STOP);
            startService(intent);
            refresh();
        });
        root.addView(stop);

        Button refresh = new Button(this);
        refresh.setText("Refresh status");
        refresh.setOnClickListener(v -> refresh());
        root.addView(refresh);

        setContentView(root);
        refresh();
    }

    private void requestAndStart() {
        if (!RootlessNativeBridge.available()) {
            status.setText("Native ARM64 bridge missing. Reinstall the latest debug APK.");
            return;
        }
        Intent permission = VpnService.prepare(this);
        if (permission != null) {
            startActivityForResult(permission, REQUEST_VPN);
        } else {
            startTestService();
        }
    }

    private void startTestService() {
        Intent intent = new Intent(this, RootlessNativeTransportService.class)
                .setAction(RootlessNativeTransportService.ACTION_START);
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(intent);
        else startService(intent);
        status.setText("Starting isolated test…");
    }

    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQUEST_VPN) {
            if (resultCode == RESULT_OK) startTestService();
            else status.setText("VPN permission declined; no test was started.");
        }
    }

    private void refresh() {
        String value = getSharedPreferences(PREFS, MODE_PRIVATE)
                .getString("status", "No native socket test has been run.");
        status.setText(value);
    }
}
