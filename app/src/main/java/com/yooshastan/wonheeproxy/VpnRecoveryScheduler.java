package com.yooshastan.wonheeproxy;

import android.app.job.JobInfo;
import android.app.job.JobScheduler;
import android.content.ComponentName;
import android.content.Context;

/**
 * Slow, best-effort recovery fallback when Android kills the optional FGS.
 * A periodic Android job can be deferred during Doze and never bypasses
 * Always-on, user stop or VPN permission checks.
 */
final class VpnRecoveryScheduler {
    private static final int JOB_ID = 8909;
    private static final long PERIOD_MILLIS = 15L * 60L * 1000L;

    private VpnRecoveryScheduler() { }

    static void update(Context context) {
        try {
            Context app = context.getApplicationContext();
            JobScheduler scheduler = (JobScheduler) app.getSystemService(
                    Context.JOB_SCHEDULER_SERVICE);
            if (scheduler == null) return;
            VpnRecoveryPreferences prefs = new VpnRecoveryPreferences(app);
            boolean wanted = prefs.enabled() && prefs.desiredOn() && !prefs.manuallyStopped();
            if (!wanted || !WireGuardSession.get(app).isAlwaysOn()) {
                scheduler.cancel(JOB_ID);
                return;
            }
            // Never repeatedly replace an active periodic job; doing so can
            // interrupt a job callback and waste battery.
            if (scheduler.getPendingJob(JOB_ID) != null) return;
            JobInfo info = new JobInfo.Builder(JOB_ID,
                    new ComponentName(app, VpnRecoveryJobService.class))
                    .setPeriodic(PERIOD_MILLIS)
                    .setPersisted(true)
                    .build();
            scheduler.schedule(info);
        } catch (RuntimeException | LinkageError unavailable) {
            // Optional periodic fallback cannot break an active WireGuard VPN.
        }
    }
}
