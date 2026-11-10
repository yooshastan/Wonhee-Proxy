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
 * Opt-in notification for ROOT-managed 1–8 kernel WireGuard tunnels.
 * Separate from the Android VpnService traffic notification; this does not
 * create an Android VPN, change firewall rules, start tunnels or read secrets.
 */
public final class RootMultiTrafficNotificationService extends Service {
    private static final String CHANNEL = "wonhee_root_tunnel_traffic_v1";
    private static final int ID = 8415;
    private static final long INTERVAL_MS = 5_000L;

    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Runnable poll = this::pollOnce;
    private NotificationManager manager;
    private boolean active;
    private boolean requestPending;
    private int emptyPolls;
    private final RootDashboardTelemetry traffic = new RootDashboardTelemetry();

    static void startIfPossible(Context context) {
        try {
            Context app = context.getApplicationContext();
            app.startForegroundService(new Intent(app, RootMultiTrafficNotificationService.class));
        } catch (RuntimeException | LinkageError denied) {
            // Notification availability must never determine VPN stack health.
        }
    }

    static void stop(Context context) {
        try {
            context.getApplicationContext().stopService(
                    new Intent(context.getApplicationContext(),
                            RootMultiTrafficNotificationService.class));
        } catch (RuntimeException | LinkageError ignored) {
            // Stopping an optional status notification cannot interrupt Safe stop.
        }
    }

    @Override public void onCreate() {
        super.onCreate();
        manager = getSystemService(NotificationManager.class);
        if (manager != null) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL, "Wonhee root tunnel speeds", NotificationManager.IMPORTANCE_LOW);
            channel.setDescription("Silent, opt-in root WireGuard upload/download speeds and "
                    + "verified DNS blocked-query totals. Not an Android system VPN indicator.");
            channel.setShowBadge(false);
            manager.createNotificationChannel(channel);
        }
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        if (active) return START_STICKY;
        if (manager == null) {
            stopSelf();
            return START_NOT_STICKY;
        }
        try {
            Notification initial = notification("Checking root tunnel counters…",
                    "No firewall or network changes; waiting for verified root tunnel state",
                    "Checking tunnels");
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(ID, initial,
                        ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
            } else {
                startForeground(ID, initial);
            }
        } catch (RuntimeException | LinkageError rejected) {
            // Android 14+ may reject an ineligible foreground service type.
            // Never claim a notification is running if startForeground fails.
            stopSelf();
            return START_NOT_STICKY;
        }
        active = true;
        handler.post(poll);
        return START_STICKY;
    }

    private void pollOnce() {
        if (!active || requestPending) return;
        requestPending = true;
        RootMultiKernelSession.get(this).readRootTrafficSnapshot(snapshot -> {
            requestPending = false;
            if (!active) return;
            if (snapshot == null) {
                handler.postDelayed(poll, INTERVAL_MS);
                return;
            }
            if (snapshot.rootsAvailable && snapshot.presentTunnels == 0) {
                if (++emptyPolls >= 2) {
                    // Root session ended or app was restarted after Safe stop.
                    stopSelf();
                    return;
                }
            } else {
                emptyPolls = 0;
            }

            String title = snapshot.presentTunnels > 0
                    && snapshot.presentTunnels == snapshot.verifiedTunnels
                    ? "Root tunnels · " + snapshot.verifiedTunnels + " verified"
                    : "Root tunnels · verification required";
            TunnelTrafficRates.Result rate = traffic.observe(
                    SystemClock.elapsedRealtime(), snapshot.countersAvailable,
                    snapshot.verifiedTunnels, snapshot.presentTunnels,
                    snapshot.received, snapshot.sent);
            String speed = snapshot.countersAvailable
                    ? rate == null ? "↓ measuring   ↑ measuring"
                            : "↓ " + TunnelTrafficRates.formatSpeed(rate.downloadMbps)
                            + "   ↑ " + TunnelTrafficRates.formatSpeed(rate.uploadMbps)
                    : "↓ unavailable   ↑ unavailable";
            String detail = snapshot.countersAvailable
                    ? "Verified tunnel traffic, not total device traffic"
                    : "Tunnel rates not verified";
            String blocked;
            if (!snapshot.dnsVerified) {
                blocked = "DNS blocking unverified";
            } else if (!snapshot.trackerEnabled) {
                blocked = "Ad & tracker blocking off";
            } else if (snapshot.blocked == null) {
                blocked = "Blocked count unavailable";
            } else {
                blocked = snapshot.blocked + " DNS requests blocked";
            }
            try {
                manager.notify(ID, notification(speed, blocked
                        + " (relay lifetime). " + detail
                        + ". Full-device kill switch unavailable.", title));
            } catch (RuntimeException | LinkageError ignored) {
                // Android notification permission may be disabled.
            }
            handler.postDelayed(poll, INTERVAL_MS);
        });
    }

    private Notification notification(String speed, String detail, String title) {
        Intent openIntent = new Intent(this, RootMultiKernelActivity.class);
        openIntent.setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        PendingIntent open = PendingIntent.getActivity(this, 1, openIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        return new Notification.Builder(this, CHANNEL)
                .setSmallIcon(R.drawable.ic_vpn_status)
                .setContentTitle("Wonhee · " + title)
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
        active = false;
        requestPending = false;
        traffic.reset();
        handler.removeCallbacksAndMessages(null);
        stopForeground(STOP_FOREGROUND_REMOVE);
        super.onDestroy();
    }

    @Override public IBinder onBind(Intent intent) { return null; }
}
