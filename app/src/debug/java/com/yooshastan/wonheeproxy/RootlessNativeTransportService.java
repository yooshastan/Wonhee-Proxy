package com.yooshastan.wonheeproxy;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.VpnService;
import android.os.Build;
import android.provider.Settings;
import android.util.Log;

/**
 * Debug-only VpnService owner for a native socket-protection smoke test.
 *
 * This test deliberately does NOT establish an OS TUN interface. Android's
 * VpnService.protect(fd) is valid once the app is prepared; creating tun0 here
 * added an unrelated network-agent lifecycle and no packet path was tested.
 * No app traffic, routes, DNS or profile endpoints are installed.
 */
public final class RootlessNativeTransportService extends VpnService {
    static final String ACTION_START = "com.yooshastan.wonheeproxy.action.NATIVE_SMOKE_START";
    static final String ACTION_STOP = "com.yooshastan.wonheeproxy.action.NATIVE_SMOKE_STOP";
    private static final String TAG = "WonheeNativeSmoke";
    private static final String PREFS = "wonhee_native_transport_smoke_v1";
    private static final String CHANNEL = "wonhee_native_transport_smoke";
    private static final int NOTIFICATION_ID = 7901;

    private long homeHandle;
    private long internetHandle;
    private boolean registered;
    private boolean foregroundStarted;
    private boolean startRequested;
    private boolean terminalReportPreserved;
    private String stage = "service-created";

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? null : intent.getAction();
        Log.i(TAG, "onStartCommand action=" + action + " startId=" + startId);
        if (ACTION_STOP.equals(action)) {
            stopTest();
            report("STOPPED — native sessions closed; protected UDP sockets released.");
            terminalReportPreserved = true;
            stopSelf(startId);
            return START_NOT_STICKY;
        }
        if (!ACTION_START.equals(action)) {
            report("STOPPED — no test requested.");
            terminalReportPreserved = true;
            stopSelf(startId);
            return START_NOT_STICKY;
        }
        if (startRequested) {
            Log.i(TAG, "duplicate start ignored at stage=" + stage);
            return START_NOT_STICKY;
        }
        startRequested = true;
        startTest();
        return START_NOT_STICKY;
    }

    private void setStage(String value) {
        stage = value;
        Log.i(TAG, "stage=" + value);
    }

    private void startTest() {
        setStage("foreground-start");
        try {
            Notification n = notification("Preparing isolated socket-protection test…");
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(NOTIFICATION_ID, n,
                        ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
            } else {
                startForeground(NOTIFICATION_ID, n);
            }
            foregroundStarted = true;
        } catch (RuntimeException failure) {
            Log.e(TAG, "Foreground start failed", failure);
            terminalReportPreserved = true;
            report("NOT PASSED — Android refused the diagnostic foreground service ("
                    + failure.getClass().getSimpleName() + ").");
            stopSelf();
            return;
        }

        try {
            setStage("native-library-preflight");
            if (!RootlessNativeBridge.available()) {
                throw new IllegalStateException("Native ARM64 bridge unavailable.");
            }

            setStage("vpn-permission-preflight");
            if (VpnService.prepare(this) != null) {
                throw new IllegalStateException("Android VPN permission is not granted.");
            }

            setStage("private-dns-preflight");
            if (!"off".equals(Settings.Global.getString(
                    getContentResolver(), "private_dns_mode"))) {
                throw new IllegalStateException("Android Private DNS must remain OFF.");
            }

            setStage("underlay-preflight");
            ConnectivityManager manager = (ConnectivityManager)
                    getSystemService(Context.CONNECTIVITY_SERVICE);
            Network active = manager == null ? null : manager.getActiveNetwork();
            NetworkCapabilities caps = active == null || manager == null
                    ? null : manager.getNetworkCapabilities(active);
            if (caps == null || caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                    || !(caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                        || caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR))) {
                throw new IllegalStateException(
                        "Disconnect other VPNs and use physical Wi-Fi or cellular.");
            }

            // Android documents protect(fd) as available after prepare();
            // establishing a TUN is not required. Keep this test out of netd's
            // interface/route lifecycle entirely.
            setStage("register-vpn-service-callback");
            if (!RootlessNativeBridge.setVpnService(this)) {
                throw new IllegalStateException("Native service callback could not be registered.");
            }
            registered = true;

            setStage("start-home-crypto-device");
            homeHandle = RootlessNativeBridge.createTestSession("home");
            if (homeHandle == 0L) {
                throw new IllegalStateException("Home crypto device or socket protection failed.");
            }

            setStage("start-internet-crypto-device");
            internetHandle = RootlessNativeBridge.createTestSession("internet");
            if (internetHandle == 0L) {
                throw new IllegalStateException("Internet crypto device or socket protection failed.");
            }

            setStage("verify-four-socket-protections");
            long[] stats = RootlessNativeBridge.protectionStats();
            if (stats.length < 2 || stats[0] != 4L || stats[1] != 0L) {
                throw new IllegalStateException("Expected four successful IPv4/IPv6 socket protections.");
            }

            setStage("passed");
            report("PASS — two independent WireGuard crypto devices started; "
                    + stats[0] + " UDP sockets protected; " + stats[1] + " failures. "
                    + "No TUN, peer endpoint, packet injection, DNS or app routes.");
            NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
            if (nm != null) nm.notify(NOTIFICATION_ID,
                    notification("2 isolated sessions · 4 sockets protected"));
        } catch (Exception | LinkageError failure) {
            Log.e(TAG, "Native protection test failed at stage=" + stage, failure);
            fail("Native protection test failed at " + stage + " ("
                    + failure.getClass().getSimpleName() + "); no app traffic was routed.");
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
        terminalReportPreserved = true;
        stopSelf();
    }

    private void report(String value) {
        Log.i(TAG, "status=" + value);
        getSharedPreferences(PREFS, MODE_PRIVATE).edit().putString("status", value).apply();
    }

    private void stopTest() {
        setStage("cleanup");
        if (internetHandle != 0L) {
            try { RootlessNativeBridge.closeSession(internetHandle); }
            catch (RuntimeException | LinkageError failure) {
                Log.e(TAG, "Internet session cleanup failed", failure);
            }
            internetHandle = 0L;
        }
        if (homeHandle != 0L) {
            try { RootlessNativeBridge.closeSession(homeHandle); }
            catch (RuntimeException | LinkageError failure) {
                Log.e(TAG, "Home session cleanup failed", failure);
            }
            homeHandle = 0L;
        }
        if (registered) {
            try { RootlessNativeBridge.clearVpnService(this); }
            catch (RuntimeException | LinkageError failure) {
                Log.e(TAG, "VPN service callback cleanup failed", failure);
            }
            registered = false;
        }
        if (foregroundStarted) {
            stopForeground(STOP_FOREGROUND_REMOVE);
            foregroundStarted = false;
        }
    }

    @Override public void onRevoke() {
        stopTest();
        report("STOPPED — Android revoked VPN permission.");
        terminalReportPreserved = true;
        stopSelf();
    }

    @Override public void onDestroy() {
        if (!terminalReportPreserved) {
            String unexpected = "STOPPED — service destroyed unexpectedly during "
                    + stage + "; no application routes were installed.";
            Log.w(TAG, unexpected);
            report(unexpected);
        }
        stopTest();
        super.onDestroy();
    }
}
