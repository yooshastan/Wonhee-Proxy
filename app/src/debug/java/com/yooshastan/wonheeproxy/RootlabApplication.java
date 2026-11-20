package com.yooshastan.wonheeproxy;

import android.app.Application;

/**
 * Debug package deliberately does not register Android VPN Always-on
 * callbacks, background recovery jobs or root traffic monitors. Only
 * explicit, user-initiated actions in RootlabTwoPeerActivity may operate
 * the kernel WireGuard links. The official application is unchanged.
 */
public final class RootlabApplication extends Application {
    @Override public void onCreate() {
        super.onCreate();
    }
}
