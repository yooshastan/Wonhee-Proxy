package com.yooshastan.wonheeproxy.core;

/**
 * Known first-party Ultgram application IDs. Mercurygram's debug build type
 * appends ".beta" to APP_PACKAGE; the FOSS package therefore becomes
 * com.yooshastan.ultmessenger.foss.beta.
 *
 * Only these explicit packages may receive proxy URLs containing secrets.
 * Do not fall back to an unscoped ACTION_VIEW or a generic app chooser.
 */
public final class UltgramPackages {
    private static final String[] KNOWN_IDS = {
            "com.yooshastan.ultmessenger.foss.beta",
            "com.yooshastan.ultmessenger.foss",
            "com.yooshastan.ultmessenger.beta",
            "com.yooshastan.ultmessenger"
    };

    private UltgramPackages() { }

    public static String[] candidates() {
        return KNOWN_IDS.clone();
    }
}
