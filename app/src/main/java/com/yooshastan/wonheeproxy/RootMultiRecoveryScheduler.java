package com.yooshastan.wonheeproxy;

import android.app.job.JobInfo;
import android.app.job.JobScheduler;
import android.content.ComponentName;
import android.content.Context;

/** Best-effort wakeups; never a guarantee of connectivity or fail-closed protection. */
final class RootMultiRecoveryScheduler {
    private static final int PERIODIC_ID = 8910;
    private static final int RETRY_ID = 8911;
    private static final long PERIOD = 15L * 60L * 1000L;

    private RootMultiRecoveryScheduler() { }

    static void afterAttempt(Context context) {
        // Replace an already-executed one-off job with the new bounded backoff
        // after all root work and rollback have completed.
        try {
            JobScheduler jobs = (JobScheduler) context.getApplicationContext()
                    .getSystemService(Context.JOB_SCHEDULER_SERVICE);
            if (jobs != null) jobs.cancel(RETRY_ID);
        } catch (RuntimeException | LinkageError ignored) { }
        update(context);
    }

    static void update(Context context) {
        try {
            Context app = context.getApplicationContext();
            JobScheduler jobs = (JobScheduler) app.getSystemService(Context.JOB_SCHEDULER_SERVICE);
            if (jobs == null) return;
            RootMultiRecoveryPreferences prefs = new RootMultiRecoveryPreferences(app);
            if (!prefs.enabled() || !prefs.desired() || prefs.manuallyStopped()
                    || prefs.failures() >= RootMultiRecoveryPolicy.MAX_FAILURES) {
                jobs.cancel(PERIODIC_ID);
                jobs.cancel(RETRY_ID);
                return;
            }
            ComponentName component = new ComponentName(app, RootMultiRecoveryJobService.class);
            if (jobs.getPendingJob(PERIODIC_ID) == null) {
                jobs.schedule(new JobInfo.Builder(PERIODIC_ID, component)
                        .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                        .setPeriodic(PERIOD)
                        .setPersisted(true)
                        .build());
            }
            // The periodic check handles long intervals. A bounded failed attempt
            // also requests a deferred single retry; Doze may delay both jobs.
            long next = prefs.nextAttemptAtMillis();
            if (next > 0L && jobs.getPendingJob(RETRY_ID) == null) {
                long delay = Math.max(1_000L, next - System.currentTimeMillis());
                jobs.schedule(new JobInfo.Builder(RETRY_ID, component)
                        .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                        .setMinimumLatency(delay)
                        .setOverrideDeadline(Math.max(delay, 30_000L))
                        .setPersisted(true)
                        .build());
            } else if (next == 0L) {
                jobs.cancel(RETRY_ID);
            }
        } catch (RuntimeException | LinkageError unavailable) {
            // Scheduling is optional and must never affect existing VPN sessions.
        }
    }
}
