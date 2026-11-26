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
import android.os.ParcelFileDescriptor;
import android.provider.Settings;
import android.util.Log;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Debug-only packet-ingress milestone.
 *
 * Exactly one Android TUN captures only this diagnostic package and only
 * 198.18.0.0/15. Two independent native WireGuard devices receive classified
 * packets through bounded PacketTun queues. Temporary keys have no endpoints,
 * so this test proves ingress/queue ownership, not a remote handshake or
 * end-to-end forwarding. No DNS, default route or root mutation is installed.
 */
public final class RootlessNativeTunPumpService extends VpnService {
    static final String ACTION_START = "com.yooshastan.wonheeproxy.action.TUN_PUMP_START";
    static final String ACTION_PROBE = "com.yooshastan.wonheeproxy.action.TUN_PUMP_PROBE";
    static final String ACTION_STOP = "com.yooshastan.wonheeproxy.action.TUN_PUMP_STOP";

    private static final String TAG = "WonheeNativeTunPump";
    private static final String PREFS = "wonhee_native_tun_pump_v1";
    private static final String CHANNEL = "wonhee_native_tun_pump";
    private static final int NOTIFICATION_ID = 7904;
    private static final int TEST_PORT = 43434;
    private static final int EXPECTED_PER_ROUTE = 3;

    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicBoolean probeRunning = new AtomicBoolean(false);
    private final AtomicInteger tunPackets = new AtomicInteger();
    private final AtomicInteger homeQueued = new AtomicInteger();
    private final AtomicInteger internetQueued = new AtomicInteger();
    private final AtomicInteger policyDrops = new AtomicInteger();
    private final AtomicInteger injectionFailures = new AtomicInteger();

    private ParcelFileDescriptor tun;
    private FileInputStream input;
    private Thread pumpThread;
    private Thread probeThread;
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
            report("STOPPED — TUN closed; native sessions closed; test-only route released.");
            terminalReportPreserved = true;
            stopSelf(startId);
            return START_NOT_STICKY;
        }
        if (ACTION_PROBE.equals(action)) {
            if (!running.get()) {
                report("NOT RUNNING — start the TUN packet pump before sending probes.");
            } else {
                sendSyntheticProbes();
            }
            return START_NOT_STICKY;
        }
        if (!ACTION_START.equals(action)) {
            report("STOPPED — no TUN packet test requested.");
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
            Notification n = notification("Preparing scoped TUN packet test…");
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

            setStage("physical-underlay-preflight");
            verifyPhysicalUnderlayAndNoOtherVpn();

            setStage("register-vpn-service-callback");
            if (!RootlessNativeBridge.setVpnService(this)) {
                throw new IllegalStateException("Native service callback could not be registered.");
            }
            registered = true;

            setStage("start-home-native-session");
            homeHandle = RootlessNativeBridge.createPacketTestSession(
                    "home", "198.18.1.0/24");
            if (homeHandle <= 0L) throw new IllegalStateException("Home native session failed.");

            setStage("start-internet-native-session");
            internetHandle = RootlessNativeBridge.createPacketTestSession(
                    "internet", "0.0.0.0/0");
            if (internetHandle <= 0L) throw new IllegalStateException("Internet native session failed.");

            setStage("verify-four-protected-sockets");
            long[] protection = RootlessNativeBridge.protectionStats();
            if (protection.length < 2 || protection[0] != 4L || protection[1] != 0L) {
                throw new IllegalStateException("Expected four protected UDP sockets and zero failures.");
            }

            setStage("establish-package-scoped-tun");
            Builder builder = new Builder()
                    .setSession("Wonhee native TUN ingress diagnostic")
                    .setMtu(1280)
                    .setBlocking(true)
                    .addAddress("10.253.0.1", 32)
                    .addRoute("198.18.0.0", 15);
            builder.addAllowedApplication(getPackageName());
            tun = builder.establish();
            if (tun == null) throw new IllegalStateException("Android did not establish the test TUN.");
            input = new FileInputStream(tun.getFileDescriptor());

            setStage("start-packet-pump");
            running.set(true);
            pumpThread = new Thread(this::pumpPackets, "WonheeNativeTunPump");
            pumpThread.setDaemon(true);
            pumpThread.start();

            setStage("ready");
            report("READY — one TUN for this package only; route 198.18.0.0/15 only. "
                    + "Two native sessions started; 4 protected sockets; no DNS, default route, "
                    + "peer endpoint or other-app routing. Send the six synthetic probes.");
            NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
            if (nm != null) nm.notify(NOTIFICATION_ID,
                    notification("TUN ready · this package + one test route only"));
        } catch (Exception | LinkageError failure) {
            Log.e(TAG, "TUN packet pump failed at stage=" + stage, failure);
            fail("TUN packet pump failed at " + stage + " ("
                    + failure.getClass().getSimpleName() + "). No other-app or default route was installed.");
        }
    }

    private void verifyPhysicalUnderlayAndNoOtherVpn() {
        ConnectivityManager manager = (ConnectivityManager)
                getSystemService(Context.CONNECTIVITY_SERVICE);
        if (manager == null) throw new IllegalStateException("Connectivity service unavailable.");
        for (Network network : manager.getAllNetworks()) {
            NetworkCapabilities caps = manager.getNetworkCapabilities(network);
            if (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                throw new IllegalStateException("Disconnect every other VPN before this test.");
            }
        }
        Network active = manager.getActiveNetwork();
        NetworkCapabilities caps = active == null ? null : manager.getNetworkCapabilities(active);
        if (caps == null || !(caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                || caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR))) {
            throw new IllegalStateException("Use physical Wi-Fi or cellular for the test.");
        }
    }

    private void pumpPackets() {
        byte[] buffer = new byte[1280];
        try {
            while (running.get()) {
                int length = input.read(buffer);
                if (length < 0) break;
                if (length == 0) continue;
                tunPackets.incrementAndGet();
                RootlessTunTestPacketRouter.Target target =
                        RootlessTunTestPacketRouter.select(buffer, length);
                long handle;
                if (target == RootlessTunTestPacketRouter.Target.HOME) handle = homeHandle;
                else if (target == RootlessTunTestPacketRouter.Target.INTERNET) handle = internetHandle;
                else {
                    policyDrops.incrementAndGet();
                    continue;
                }
                int result = RootlessNativeBridge.injectPacket(handle, Arrays.copyOf(buffer, length));
                if (result != 1) {
                    injectionFailures.incrementAndGet();
                } else if (target == RootlessTunTestPacketRouter.Target.HOME) {
                    homeQueued.incrementAndGet();
                } else {
                    internetQueued.incrementAndGet();
                }
            }
        } catch (IOException failure) {
            if (running.get()) {
                Log.e(TAG, "TUN read failed", failure);
                running.set(false);
                terminalReportPreserved = true;
                report("NOT PASSED — TUN packet reader stopped unexpectedly; releasing the TUN.");
                stopSelf();
            }
        } finally {
            if (running.get()) {
                running.set(false);
                terminalReportPreserved = true;
                report("NOT PASSED — TUN packet reader ended unexpectedly; releasing the TUN.");
                stopSelf();
            }
        }
    }

    private void sendSyntheticProbes() {
        if (!probeRunning.compareAndSet(false, true)) return;
        Thread worker = new Thread(() -> {
            try (DatagramSocket socket = new DatagramSocket()) {
                byte[] payload = new byte[] {0x57, 0x4E, 0x54, 0x55, 0x4E, 0x31};
                InetAddress home = InetAddress.getByAddress(
                        new byte[] {(byte) 198, 18, 1, 10});
                InetAddress internet = InetAddress.getByAddress(
                        new byte[] {(byte) 198, 18, 2, 10});
                for (int i = 0; i < EXPECTED_PER_ROUTE && running.get(); i++) {
                    socket.send(new DatagramPacket(payload, payload.length, home, TEST_PORT));
                    if (!running.get()) break;
                    socket.send(new DatagramPacket(payload, payload.length, internet, TEST_PORT));
                }
            } catch (Exception failure) {
                if (running.get()) {
                    report("PROBE SEND FAILED — " + failure.getClass().getSimpleName());
                }
                probeRunning.set(false);
                return;
            }

            long deadline = System.currentTimeMillis() + 5000L;
            long[] homeStats = new long[] {-1L, -1L, -1L};
            long[] internetStats = new long[] {-1L, -1L, -1L};
            while (running.get() && System.currentTimeMillis() < deadline) {
                homeStats = RootlessNativeBridge.packetStats(homeHandle);
                internetStats = RootlessNativeBridge.packetStats(internetHandle);
                if (homeStats.length >= 3 && internetStats.length >= 3
                        && homeStats[1] >= EXPECTED_PER_ROUTE
                        && internetStats[1] >= EXPECTED_PER_ROUTE) break;
                try { Thread.sleep(50L); }
                catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
            reportResult(homeStats, internetStats);
            probeRunning.set(false);
        }, "WonheeNativeTunProbes");
        worker.setDaemon(true);
        probeThread = worker;
        worker.start();
    }

    private void reportResult(long[] homeStats, long[] internetStats) {
        long[] protection = RootlessNativeBridge.protectionStats();
        boolean pass = tunPackets.get() >= EXPECTED_PER_ROUTE * 2
                && homeQueued.get() >= EXPECTED_PER_ROUTE
                && internetQueued.get() >= EXPECTED_PER_ROUTE
                && homeStats.length >= 3 && internetStats.length >= 3
                && homeStats[1] >= EXPECTED_PER_ROUTE
                && internetStats[1] >= EXPECTED_PER_ROUTE
                && homeStats[2] == 0L && internetStats[2] == 0L
                && policyDrops.get() == 0 && injectionFailures.get() == 0
                && protection.length >= 2 && protection[0] == 4L && protection[1] == 0L;
        String value = String.format(Locale.US,
                "%s — TUN packets=%d; Home injected/read=%d/%d; Internet injected/read=%d/%d; "
                        + "policy drops=%d; injection failures=%d; protected sockets=%d; protection failures=%d. "
                        + "No peer endpoints, handshakes, DNS or reply path were used.",
                pass ? "PASS" : "NOT PASSED",
                tunPackets.get(),
                homeStats.length > 0 ? homeStats[0] : -1L,
                homeStats.length > 1 ? homeStats[1] : -1L,
                internetStats.length > 0 ? internetStats[0] : -1L,
                internetStats.length > 1 ? internetStats[1] : -1L,
                policyDrops.get(), injectionFailures.get(),
                protection.length > 0 ? protection[0] : -1L,
                protection.length > 1 ? protection[1] : -1L);
        report(value);
    }

    private Notification notification(String message) {
        NotificationManager manager = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (manager != null && Build.VERSION.SDK_INT >= 26) {
            manager.createNotificationChannel(new NotificationChannel(
                    CHANNEL, "Wonhee native TUN packet test", NotificationManager.IMPORTANCE_LOW));
        }
        Intent open = new Intent(this, RootlessNativeTunPumpActivity.class);
        PendingIntent pending = PendingIntent.getActivity(this, NOTIFICATION_ID, open,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        return new Notification.Builder(this, CHANNEL)
                .setSmallIcon(R.drawable.ic_vpn_status)
                .setContentTitle("Wonhee native TUN packet test")
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
        running.set(false);
        if (probeThread != null && probeThread != Thread.currentThread()) {
            probeThread.interrupt();
            try { probeThread.join(500L); }
            catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
            probeThread = null;
        }
        if (tun != null) {
            try { tun.close(); } catch (IOException failure) {
                Log.e(TAG, "TUN close failed", failure);
            }
            tun = null;
        }
        if (input != null) {
            try { input.close(); } catch (IOException failure) {
                Log.e(TAG, "TUN input close failed", failure);
            }
            input = null;
        }
        if (pumpThread != null && pumpThread != Thread.currentThread()) {
            try { pumpThread.join(500L); }
            catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
            pumpThread = null;
        }
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
        if (foregroundStarted) {
            stopForeground(STOP_FOREGROUND_REMOVE);
            foregroundStarted = false;
        }
    }

    @Override public void onRevoke() {
        stopTest();
        report("STOPPED — Android revoked VPN permission; TUN and native sessions released.");
        terminalReportPreserved = true;
        stopSelf();
    }

    @Override public void onDestroy() {
        if (!terminalReportPreserved) {
            report("STOPPED — service destroyed unexpectedly during " + stage
                    + "; native sessions and TUN are being released.");
        }
        stopTest();
        super.onDestroy();
    }
}
