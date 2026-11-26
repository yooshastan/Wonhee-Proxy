package com.yooshastan.wonheeproxy;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.provider.Settings;

import java.io.IOException;

/**
 * Debug-only VPN owner for a no-route socket-protection experiment.
 * The TUN has an address but deliberately has NO routes: no app traffic enters it.
 */
public final class RootlessNativeTransportService extends VpnService {
    static final String ACTION_START = "com.yooshastan.wonheeproxy.action.NATIVE_SMOKE_START";
    static final String ACTION_STOP = "com.yooshastan.wonheeproxy.action.NATIVE_SMOKE_STOP";
    private static final String PREFS = "wonhee_native_transport_smoke_v1";
    private static final String CHANNEL = "wonhee_native_transport_smoke";
    private static final int NOTIFICATION_ID = 7901;

    private ParcelFileDescriptor tun;
    private long homeHandle;
    private long internetHandle;
    private boolean registered;

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? null : intent.getAction();
        if (ACTION_STOP.equals(action)) {
            stopTest();
            stopSelf(startId);
            return START_NOT_STICKY;
        }
        if (!ACTION_START.equals(action)) {
            report("STOPPED — no test requested.");
            stopSelf(startId);
            return START_NOT_STICKY;
        }
        startTest();
        return START_NOT_STICKY;
    }

    private void startTest() {
        if (tun != null) return;
        if (!RootlessNativeBridge.available()) {
            fail("Native ARM64 bridge unavailable in this APK.");
            return;
        }
        if (VpnService.prepare(this) != null) {
            fail("Android VPN permission is not granted. Open the test screen and approve it.");
            return;
        }
        if (!"off".equals(Settings.Global.getString(
                getContentResolver(), "private_dns_mode"))) {
            fail("Android Private DNS must remain OFF for this test.");
            return;
        }
        ConnectivityManager manager = (ConnectivityManager)
                getSystemService(Context.CONNECTIVITY_SERVICE);
        Network active = manager == null ? null : manager.getActiveNetwork();
        NetworkCapabilities caps = active == null || manager == null
                ? null : manager.getNetworkCapabilities(active);
        if (caps == null || caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                || !(caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                    || caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR))) {
            fail("Disconnect other VPNs and use a physical Wi-Fi or cellular network.");
            return;
        }

        try {
            startForeground(NOTIFICATION_ID, notification(
                    "Preparing isolated socket-protection test…"));
            tun = new Builder()
                    .setSession("Wonhee native socket protection test")
                    .addAddress("10.255.255.1", 32)
                    .establish();
            if (tun == null) throw new IllegalStateException("Android did not establish the test TUN.");
            if (!RootlessNativeBridge.setVpnService(this)) {
                throw new IllegalStateException("Native service callback could not be registered.");
            }
            registered = true;
            homeHandle = RootlessNativeBridge.createTestSession("home");
            if (homeHandle == 0L) throw new IllegalStateException("Home crypto session failed to start.");
            internetHandle = RootlessNativeBridge.createTestSession("internet");
            if (internetHandle == 0L) throw new IllegalStateException("Internet crypto session failed to start.");

            long[] stats = RootlessNativeBridge.protectionStats();
            if (stats.length < 2 || stats[0] != 4L || stats[1] != 0L) {
                throw new IllegalStateException("Expected four successful IPv4/IPv6 socket protections.");
            }
            report("PASS — two independent WireGuard crypto devices started; "
                    + stats[0] + " UDP sockets protected; " + stats[1] + " failures. "
                    + "No peer endpoint, packet injection, DNS or app routes.");
            NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
            if (nm != null) nm.notify(NOTIFICATION_ID, notification("2 isolated sessions · 4 sockets protected"));
        } catch (Exception | LinkageError failure) {
            // Never surface JNI, native runtime or profile details in the test UI.
            fail("Native protection test failed; no app traffic was routed.");
        }
    }

    private Notification notification(String message) {
        NotificationManager manager = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (manager != null && Build.VERSION.SDK_INT >= 26) {
            manager.createNotificationChannel(new NotificationChannel(
                    CHANNEL, "Wonhee native socket test", NotificationManager.IMPORTANCE_LOW));
        }
        Intent open = new Intent(this, RootlessNativeTransportActivity.class);
        PendingIntent pending = PendingIntent.getActivity(this, 7901, open,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        return new Notification.Builder(this, CHANNEL)
                .setSmallIcon(R.drawable.ic_vpn_status)
                .setContentTitle("Wonhee native transport lab")
                .setContentText(message)
                .setContentIntent(pending)
                .setOngoing(true)
                .build();
    }

    private void fail(String message) {
        stopTest();
        report("NOT PASSED — " + message);
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelf();
    }

    private void report(String value) {
        getSharedPreferences(PREFS, MODE_PRIVATE).edit().putString("status", value).apply();
    }

    private void stopTest() {
        if (internetHandle != 0L) {
            RootlessNativeBridge.closeSession(internetHandle);
            internetHandle = 0L;
        }
        if (homeHandle != 0L) {
            RootlessNativeBridge.closeSession(homeHandle);
            homeHandle = 0L;
        }
        if (registered) {
            RootlessNativeBridge.clearVpnService(this);
            registered = false;
        }
        if (tun != null) {
            try { tun.close(); } catch (IOException ignored) { }
            tun = null;
        }
        stopForeground(STOP_FOREGROUND_REMOVE);
        report("STOPPED — native sessions closed; protected UDP sockets released.");
    }

    @Override public void onRevoke() {
        stopTest();
        report("STOPPED — Android revoked VPN permission.");
        stopSelf();
    }

    @Override public void onDestroy() {
        stopTest();
        super.onDestroy();
    }
}
