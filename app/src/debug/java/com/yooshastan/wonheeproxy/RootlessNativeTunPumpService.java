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
import android.os.SystemClock;
import android.provider.Settings;
import android.util.Log;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.Locale;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicIntegerArray;
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
    private final AtomicIntegerArray rejectionCounts = new AtomicIntegerArray(RootlessTunTestPacketRouter.Reason.values().length);
    private volatile ProbeBatch activeBatch;

    private static final class ProbeBatch {
        final int port;
        final byte[] nonce = new byte[16];
        final AtomicInteger seen = new AtomicInteger();
        final AtomicInteger duplicates = new AtomicInteger();
        ProbeBatch(int port) { this.port = port; new SecureRandom().nextBytes(nonce); }
    }

    private void reject(RootlessTunTestPacketRouter.Reason reason) {
        policyDrops.incrementAndGet();
        rejectionCounts.incrementAndGet(reason.ordinal());
    }

    private String rejectionSummary() {
        StringBuilder out = new StringBuilder();
        for (RootlessTunTestPacketRouter.Reason reason : RootlessTunTestPacketRouter.Reason.values()) {
            int count = rejectionCounts.get(reason.ordinal());
            if (count != 0) out.append(reason.name()).append('=').append(count).append(' ');
        }
        return out.length() == 0 ? "none" : out.toString().trim();
    }

    private ParcelFileDescriptor tun;
    private FileInputStream input;
    private Thread pumpThread;
    private Thread probeThread;
    private long homeHandle;
    private long internetHandle;
    private boolean registered;
    private boolean foregroundStarted;
    private boolean startRequested;
    private volatile boolean terminalReportPreserved;
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
                RootlessTunTestPacketRouter.Reason reason = RootlessTunTestPacketRouter.rejection(buffer, length);
                if (reason != null) { reject(reason); continue; }
                ProbeBatch batch = activeBatch;
                if (batch == null) { reject(RootlessTunTestPacketRouter.Reason.OUTSIDE_BATCH); continue; }
                int index = RootlessTunTestPacketRouter.probeIndex(buffer, length, batch.port, batch.nonce);
                if (index < 0) { reject(RootlessTunTestPacketRouter.Reason.PROBE_MISMATCH); continue; }
                int bit = 1 << index;
                if ((batch.seen.get() & bit) != 0) {
                    batch.duplicates.incrementAndGet();
                    reject(RootlessTunTestPacketRouter.Reason.DUPLICATE);
                    continue;
                }
                RootlessTunTestPacketRouter.Target target =
                        RootlessTunTestPacketRouter.select(buffer, length);
                long handle;
                if (target == RootlessTunTestPacketRouter.Target.HOME) handle = homeHandle;
                else if (target == RootlessTunTestPacketRouter.Target.INTERNET) handle = internetHandle;
                else {
                    reject(RootlessTunTestPacketRouter.Reason.PROBE_MISMATCH);
                    continue;
                }
                int result = RootlessNativeBridge.injectPacket(handle, Arrays.copyOf(buffer, length));
                if (result != 1) {
                    injectionFailures.incrementAndGet();
                } else {
                    if (target == RootlessTunTestPacketRouter.Target.HOME) homeQueued.incrementAndGet();
                    else internetQueued.incrementAndGet();
                    batch.seen.getAndUpdate(value -> value | bit);
                }
            }
        } catch (Exception | LinkageError failure) {
            if (running.get()) {
                Log.e(TAG, "TUN packet pump failed", failure);
                running.set(false);
                terminalReportPreserved = true;
                report("NOT PASSED — TUN packet pump failed ("
                        + failure.getClass().getSimpleName() + "); releasing the TUN.");
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
                if (!running.get()) return;
                long[] homeBefore = RootlessNativeBridge.packetStats(homeHandle);
                long[] internetBefore = RootlessNativeBridge.packetStats(internetHandle);
                if (!validStats(homeBefore) || !validStats(internetBefore)) {
                    if (running.get()) report("NOT PASSED — native baseline unavailable.");
                    return;
                }
                int failureBefore = injectionFailures.get();
                ProbeBatch batch = new ProbeBatch(socket.getLocalPort());
                activeBatch = batch;
                InetAddress home = InetAddress.getByAddress(new byte[] {(byte) 198, 18, 1, 10});
                InetAddress internet = InetAddress.getByAddress(new byte[] {(byte) 198, 18, 2, 10});
                for (int i = 0; i < 6 && running.get(); i++) {
                    byte[] payload = Arrays.copyOf(batch.nonce, 17);
                    payload[16] = (byte) i;
                    socket.send(new DatagramPacket(payload, payload.length,
                            i % 2 == 0 ? home : internet, TEST_PORT));
                }

                long deadline = SystemClock.elapsedRealtime() + 5000L;
                long[] h = new long[] {-1L, -1L, -1L};
                long[] n = new long[] {-1L, -1L, -1L};
                while (running.get() && SystemClock.elapsedRealtime() < deadline) {
                    h = RootlessNativeBridge.packetStats(homeHandle);
                    n = RootlessNativeBridge.packetStats(internetHandle);
                    if (batch.seen.get() == 63 && validStats(h) && validStats(n)
                            && h[1] - homeBefore[1] >= EXPECTED_PER_ROUTE
                            && n[1] - internetBefore[1] >= EXPECTED_PER_ROUTE) break;
                    Thread.sleep(50L);
                }
                if (running.get()) reportResult(batch, homeBefore, internetBefore, h, n, failureBefore);
            } catch (InterruptedException stopped) {
                Thread.currentThread().interrupt();
            } catch (Exception | LinkageError failure) {
                if (running.get()) report("NOT PASSED — probe worker failed: " + failure.getClass().getSimpleName());
            } finally {
                activeBatch = null;
                probeRunning.set(false);
            }
        }, "WonheeNativeTunProbes");
        worker.setDaemon(true);
        probeThread = worker;
        worker.start();
    }

    private static boolean validStats(long[] stats) {
        return stats != null && stats.length >= 3 && stats[0] >= 0 && stats[1] >= 0 && stats[2] >= 0;
    }

    private static long delta(long[] after, long[] before, int field) {
        return validStats(after) && validStats(before) ? after[field] - before[field] : -1L;
    }

    private void reportResult(ProbeBatch batch, long[] hb, long[] nb,
                              long[] h, long[] n, int failureBefore) {
        long hi = delta(h, hb, 0), hr = delta(h, hb, 1), hd = delta(h, hb, 2);
        long ni = delta(n, nb, 0), nr = delta(n, nb, 1), nd = delta(n, nb, 2);
        long[] protection = RootlessNativeBridge.protectionStats();
        int failures = injectionFailures.get() - failureBefore;
        boolean pass = running.get() && batch.seen.get() == 63 && batch.duplicates.get() == 0
                && hi == 3 && hr == 3 && ni == 3 && nr == 3
                && hd == 0 && nd == 0 && failures == 0
                && protection != null && protection.length >= 2 && protection[0] == 4L && protection[1] == 0L;
        report(String.format(Locale.US,
                "%s — current batch unique probes=%d/6; Home injected/read=%d/%d; Internet injected/read=%d/%d; "
                        + "duplicates=%d; native drops=%d/%d; injection failures=%d; protected sockets=%d; protection failures=%d. "
                        + "Session totals: TUN packets=%d; rejected by policy=%d (%s). "
                        + "Rejected packets never enter native queues. No peer endpoints, handshakes, DNS or reply path.",
                pass ? "PASS" : "NOT PASSED", Integer.bitCount(batch.seen.get()), hi, hr, ni, nr,
                batch.duplicates.get(), hd, nd, failures,
                protection != null && protection.length > 0 ? protection[0] : -1L,
                protection != null && protection.length > 1 ? protection[1] : -1L,
                tunPackets.get(), policyDrops.get(), rejectionSummary()));
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
