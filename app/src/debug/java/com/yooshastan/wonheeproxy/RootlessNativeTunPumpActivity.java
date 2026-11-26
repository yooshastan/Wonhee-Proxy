package com.yooshastan.wonheeproxy;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

/** Debug-only UI for the narrow TUN-to-native-queue packet pump test. */
public final class RootlessNativeTunPumpActivity extends Activity {
    private static final int REQUEST_VPN = 7903;
    private static final String PREFS = "wonhee_native_tun_pump_v1";
    private TextView status;

    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (getResources().getDisplayMetrics().density * 18);
        root.setPadding(pad, pad, pad, pad);

        TextView heading = new TextView(this);
        heading.setText("Native TUN packet pump · diagnostic");
        heading.setTextSize(21);
        root.addView(heading);

        TextView explanation = new TextView(this);
        explanation.setText(
                "This debug-only test establishes ONE Android VPN/TUN for the Wonhee test "
                + "package only. It installs ONE IPv4 route: 198.18.0.0/15 (reserved "
                + "benchmarking space). 198.18.1.0/24 is classified as Home; the rest "
                + "of that test range is classified as Internet exit. Six synthetic UDP "
                + "datagrams are sent into the TUN and queued to two independent native "
                + "WireGuard devices using temporary keys.\n\n"
                + "No user profiles, peer endpoints, DNS, credentials, root commands, "
                + "default routes or other-app routing are used. No remote handshake or "
                + "reply path is claimed. IPv6 and non-UDP packets are outside this test.\n\n"
                + "Stop the 0.15.81 socket-only test using its Stop test and release sockets button. Use Exact-owned Safe Stop for any active RootLab kernel links, then disconnect every other VPN. Android Private DNS must remain OFF.");
        explanation.setTextSize(14);
        root.addView(explanation);

        status = new TextView(this);
        status.setTextSize(15);
        status.setPadding(0, pad, 0, pad);
        root.addView(status, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        Button start = new Button(this);
        start.setText("Start TUN packet pump test");
        start.setOnClickListener(v -> requestAndStart());
        root.addView(start);

        Button probe = new Button(this);
        probe.setText("Send six synthetic Home + Internet probes");
        probe.setOnClickListener(v -> sendProbes());
        root.addView(probe);

        Button stop = new Button(this);
        stop.setText("Stop test and release TUN");
        stop.setOnClickListener(v -> stopTest());
        root.addView(stop);

        Button refresh = new Button(this);
        refresh.setText("Refresh status");
        refresh.setOnClickListener(v -> refresh());
        root.addView(refresh);

        ScrollView scroller = new ScrollView(this);
        scroller.setFillViewport(true);
        scroller.setClipToPadding(false);
        scroller.addView(root, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        scroller.setOnApplyWindowInsetsListener((view, insets) -> {
            int bottom = Build.VERSION.SDK_INT >= 30
                    ? insets.getInsets(WindowInsets.Type.systemBars()).bottom
                    : insets.getSystemWindowInsetBottom();
            view.setPadding(0, 0, 0, bottom);
            return insets;
        });
        setContentView(scroller);
        refresh();
    }

    private void requestAndStart() {
        if (!RootlessNativeBridge.available()) {
            status.setText("Native ARM64 bridge missing. Reinstall the latest diagnostic APK.");
            return;
        }
        Intent permission = VpnService.prepare(this);
        if (permission != null) startActivityForResult(permission, REQUEST_VPN);
        else startTestService();
    }

    private void startTestService() {
        Intent intent = new Intent(this, RootlessNativeTunPumpService.class)
                .setAction(RootlessNativeTunPumpService.ACTION_START);
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(intent);
        else startService(intent);
        status.setText("Starting isolated TUN packet pump…");
    }

    private void sendProbes() {
        Intent intent = new Intent(this, RootlessNativeTunPumpService.class)
                .setAction(RootlessNativeTunPumpService.ACTION_PROBE);
        startService(intent);
        status.setText("Sending synthetic UDP probes…");
    }

    private void stopTest() {
        Intent intent = new Intent(this, RootlessNativeTunPumpService.class)
                .setAction(RootlessNativeTunPumpService.ACTION_STOP);
        startService(intent);
        refresh();
    }

    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQUEST_VPN) {
            if (resultCode == RESULT_OK) startTestService();
            else status.setText("VPN permission declined; no test was started.");
        }
    }

    private void refresh() {
        status.setText(getSharedPreferences(PREFS, MODE_PRIVATE)
                .getString("status", "No TUN packet pump test has been run."));
    }
}
