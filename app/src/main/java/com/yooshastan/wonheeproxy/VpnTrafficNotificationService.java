package com.yooshastan.wonheeproxy;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.SystemClock;

/**
 * Silent foreground notification of WireGuard's local RX/TX counters.
 * The optional opt-in monitor may also request encrypted-profile restoration
 * when the WireGuard interface is actually DOWN. It performs no network probes.
 * A VPN can remain connected if Android refuses to start this optional service.
 */
public final class VpnTrafficNotificationService extends Service {
    private static final String CHANNEL_ID = "wonhee_vpn_tunnel_status_v1";
    private static final int NOTIFICATION_ID = 8405;
    private static final long REFRESH_MILLIS = 5_000L;

    private final Handler handler = new Handler(Looper.getMainLooper());
    private NotificationManager manager;
    private boolean running;
    private TunnelTrafficRates.Sample previous;
    private final VpnRecoveryBackoff recoveryBackoff = new VpnRecoveryBackoff();
    private boolean recoveryPending;
    private boolean lastInterfaceUp = true;

    static void startIfPossible(Context context) {
        try {
            Context app = context.getApplicationContext();
            app.startForegroundService(new Intent(app, VpnTrafficNotificationService.class));
        } catch (RuntimeException | LinkageError unavailable) {
            // Android may refuse background foreground-service launches,
            // especially during system Always-on restoration. The VPN is
            // intentionally independent of this optional notification.
        }
    }

    static void stop(Context context) {
        try {
            Context app = context.getApplicationContext();
            app.stopService(new Intent(app, VpnTrafficNotificationService.class));
        } catch (RuntimeException | LinkageError ignored) {
            // Notification cleanup must never interrupt VPN teardown.
        }
    }

    @Override public void onCreate() {
        super.onCreate();
        manager = getSystemService(NotificationManager.class);
        if (manager != null) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID, "Wonhee VPN traffic", NotificationManager.IMPORTANCE_LOW);
            channel.setDescription("Silent WireGuard tunnel connection and throughput status");
            channel.setShowBadge(false);
            manager.createNotificationChannel(channel);
        }
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        if (manager == null) {
            stopSelf();
            return START_NOT_STICKY;
        }
        if (running) return START_STICKY;
        try {
            Notification initial = makeNotification("Measuring tunnel traffic...",
                    "Passive WireGuard RX/TX counters only");
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(NOTIFICATION_ID, initial,
                        ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED);
            } else {
                startForeground(NOTIFICATION_ID, initial);
            }
        } catch (RuntimeException | LinkageError unavailable) {
            // Do not sacrifice a working VPN for the notification. This may
            // happen when the system rejects the systemExempted FGS type.
            stopSelf();
            return START_NOT_STICKY;
        }
        running = true;
        previous = null;
        handler.post(this::pollOnce);
        return START_STICKY;
    }

    private void pollOnce() {
        if (!running) return;
        try {
            WireGuardSession.get(this).readStatistics(snapshot -> {
                if (!running) return;
                if (!snapshot.interfaceUp) {
                    previous = null;
                    lastInterfaceUp = false;
                    WireGuardSession session = WireGuardSession.get(this);
                    VpnRecoveryPreferences prefs = new VpnRecoveryPreferences(this);
                    if (!prefs.canRetry(session.isAlwaysOn())) {
                        stopSelf();
                        return;
                    }
                    long now = SystemClock.elapsedRealtime();
                    if (!recoveryPending && !session.isBusy() && recoveryBackoff.isDue(now)) {
                        recoveryPending = true;
                        session.recoverSavedProfileIfDesired((success, message) -> {
                            recoveryPending = false;
                            if (success) recoveryBackoff.reset();
                            else recoveryBackoff.failed(SystemClock.elapsedRealtime());
                        });
                    }
                    String next = recoveryPending ? "Recovery attempt underway"
                            : "Retry in " + recoveryBackoff.secondsUntilNext(now) + "s";
                    try {
                        manager.notify(NOTIFICATION_ID, makeNotification(
                                "VPN interface down · Auto-reconnect ON",
                                next + ". Android lockdown remains unchanged."));
                    } catch (RuntimeException | LinkageError ignored) {
                        // Notifications are optional; never disable lockdown.
                    }
                    handler.postDelayed(this::pollOnce, REFRESH_MILLIS);
                    return;
                }
                lastInterfaceUp = true;
                recoveryBackoff.reset();
                String speed = "Traffic statistics unavailable";
                String detail = "The VPN interface is active; no traffic audit is running.";
                if (snapshot.statisticsAvailable) {
                    TunnelTrafficRates.Sample next = new TunnelTrafficRates.Sample(
                            SystemClock.elapsedRealtime(), snapshot.receivedBytes,
                            snapshot.transmittedBytes);
                    TunnelTrafficRates.Result result = TunnelTrafficRates.calculate(previous, next);
                    previous = next;
                    speed = result == null ? "Measuring tunnel traffic..."
                            : "↓ " + TunnelTrafficRates.formatSpeed(result.downloadMbps)
                            + "  ↑ " + TunnelTrafficRates.formatSpeed(result.uploadMbps);
                    detail = "Total ↓ " + TunnelTrafficRates.formatTotal(snapshot.receivedBytes)
                            + " · ↑ " + TunnelTrafficRates.formatTotal(snapshot.transmittedBytes)
                            + ". Tunnel only; not a DNS or traffic leak test.";
                } else {
                    previous = null;
                }
                try {
                    manager.notify(NOTIFICATION_ID, makeNotification(speed, detail));
                } catch (RuntimeException | LinkageError ignored) {
                    // Notification permission can be denied without affecting VPN.
                }
                handler.postDelayed(this::pollOnce, REFRESH_MILLIS);
            });
        } catch (RuntimeException | LinkageError failure) {
            previous = null;
            handler.postDelayed(this::pollOnce, REFRESH_MILLIS);
        }
    }

    private Notification makeNotification(String speed, String detail) {
        Intent launch = new Intent(this, VpnActivity.class);
        launch.setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        PendingIntent open = PendingIntent.getActivity(this, 0, launch,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        return new Notification.Builder(this, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_vpn_status)
                .setContentTitle(lastInterfaceUp
                        ? "Wonhee VPN · Interface active" : "Wonhee VPN · Reconnecting")
                .setContentText(speed)
                .setStyle(new Notification.BigTextStyle().bigText(speed + "\n" + detail))
                .setContentIntent(open)
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .setShowWhen(false)
                .setCategory(Notification.CATEGORY_SERVICE)
                .setVisibility(Notification.VISIBILITY_PRIVATE)
                .build();
    }

    @Override public void onDestroy() {
        running = false;
        previous = null;
        recoveryPending = false;
        recoveryBackoff.reset();
        handler.removeCallbacksAndMessages(null);
        stopForeground(STOP_FOREGROUND_REMOVE);
        super.onDestroy();
    }

    @Override public IBinder onBind(Intent intent) {
        return null;
    }
}
