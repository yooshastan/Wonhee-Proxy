package com.yooshastan.wonheeproxy;

import android.app.job.JobParameters;
import android.app.job.JobService;
import android.os.UserManager;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/** Serial root recovery after consent, within Android's best-effort job policy. */
public final class RootMultiRecoveryJobService extends JobService {
    private final ConcurrentHashMap<Integer, AtomicBoolean> jobs = new ConcurrentHashMap<>();

    @Override public boolean onStartJob(JobParameters params) {
        try {
            UserManager users = (UserManager) getSystemService(USER_SERVICE);
            if (users != null && !users.isUserUnlocked()) return false;
            RootMultiRecoveryPreferences prefs = new RootMultiRecoveryPreferences(this);
            RootMultiKernelSession session = RootMultiKernelSession.get(this);
            if (!prefs.canAttempt(System.currentTimeMillis()) || session.isBusy()) return false;
            AtomicBoolean cancelled = new AtomicBoolean(false);
            jobs.put(params.getJobId(), cancelled);
            session.recoverSavedIfDesired((ok, status) -> {
                jobs.remove(params.getJobId(), cancelled);
                if (!cancelled.get()) {
                    try { jobFinished(params, false); }
                    catch (RuntimeException ignored) { /* Job was stopped by Android. */ }
                }
            }, cancelled::get);
            return true;
        } catch (RuntimeException | LinkageError unavailable) {
            return false;
        }
    }

    @Override public boolean onStopJob(JobParameters params) {
        AtomicBoolean cancelled = jobs.remove(params.getJobId());
        if (cancelled != null) cancelled.set(true);
        return false;
    }
}
