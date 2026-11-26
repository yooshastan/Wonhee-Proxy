package com.yooshastan.wonheeproxy;

import android.net.VpnService;

/** Debug-only JNI entry points for the native protected-socket smoke test. */
final class RootlessNativeBridge {
    private static final boolean LOADED;
    static {
        boolean loaded;
        try {
            System.loadLibrary("wonhee_native");
            loaded = true;
        } catch (UnsatisfiedLinkError unavailable) {
            loaded = false;
        }
        LOADED = loaded;
    }

    private RootlessNativeBridge() {}
    static boolean available() { return LOADED; }
    static boolean setVpnService(VpnService service) {
        return LOADED && nativeSetVpnService(service);
    }
    static boolean clearVpnService(VpnService service) {
        return LOADED && nativeClearVpnService(service);
    }
    static long createTestSession(String name) {
        return LOADED ? nativeCreateTestSession(name) : 0L;
    }
    static boolean closeSession(long handle) {
        return LOADED && handle != 0L && nativeCloseSession(handle);
    }
    static long[] protectionStats() {
        return LOADED ? nativeProtectionStats() : new long[] {0L, 0L};
    }

    private static native boolean nativeSetVpnService(VpnService service);
    private static native boolean nativeClearVpnService(VpnService service);
    private static native long nativeCreateTestSession(String name);
    private static native boolean nativeCloseSession(long handle);
    private static native long[] nativeProtectionStats();
}
