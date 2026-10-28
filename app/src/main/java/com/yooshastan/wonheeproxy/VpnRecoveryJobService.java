package com.yooshastan.wonheeproxy;

import android.app.job.JobParameters;
import android.app.job.JobService;

/**
 * Periodic fallback. No network probe, DNS lookup, or direct connection:
 * it only checks the local WireGuard interface and, if explicitly permitted,
 * tries to restore the encrypted profile using the normal serialized backend.
 */
public final class VpnRecoveryJobService extends JobService {
    private volatile boolean stopped;

    @Override public boolean onStartJob(JobParameters params) {
        stopped = false;
        try {
            VpnRecoveryPreferences prefs = new VpnRecoveryPreferences(this);
            WireGuardSession session = WireGuardSession.get(this);
            if (!prefs.canRetry(session.isAlwaysOn()) || session.isConnected()
                    || session.isBusy()) return false;

            session.recoverSavedProfileIfDesired((success, message) -> {
                if (!stopped) {
                    try {
                        jobFinished(params, false);
                    } catch (RuntimeException ignored) {
                        // The scheduler may have already stopped this job.
                    }
                }
            });
            return true;
        } catch (RuntimeException | LinkageError unavailable) {
            return false;
        }
    }

    @Override public boolean onStopJob(JobParameters params) {
        stopped = true;
        return false;
    }
}
