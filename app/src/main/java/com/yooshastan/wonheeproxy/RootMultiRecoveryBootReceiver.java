package com.yooshastan.wonheeproxy;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/** Only schedules deferred checks; never performs root operations in a broadcast. */
public final class RootMultiRecoveryBootReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context context, Intent intent) {
        if (Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())
                || Intent.ACTION_USER_UNLOCKED.equals(intent.getAction())) {
            RootMultiRecoveryScheduler.update(context);
        }
    }
}
