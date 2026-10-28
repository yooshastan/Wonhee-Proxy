package com.yooshastan.wonheeproxy;

import android.app.PendingIntent;
import android.content.Intent;
import android.os.Build;
import android.service.quicksettings.TileService;

/**
 * User-added Quick Settings shortcut. Opens the dashboard only; it never
 * changes VPN state from a locked screen or bypasses Android VPN permission.
 */
public final class WonheeQuickSettingsTile extends TileService {
    @Override public void onClick() {
        super.onClick();
        Intent open = new Intent(this, VpnActivity.class)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        try {
            if (Build.VERSION.SDK_INT >= 34) {
                PendingIntent pending = PendingIntent.getActivity(this, 8701, open,
                        PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
                startActivityAndCollapse(pending);
            } else {
                startActivityAndCollapse(open);
            }
        } catch (RuntimeException | LinkageError unavailable) {
            // Optional shortcut must never interfere with the VPN.
        }
    }
}
