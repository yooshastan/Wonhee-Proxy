package com.yooshastan.wonheeproxy;

import android.net.VpnService;

/** Debug-only JNI entry points for protected WireGuard sockets and TUN queues. */
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
    static long createPacketTestSession(String name, String allowedIp) {
        return LOADED ? nativeCreatePacketTestSession(name, allowedIp) : 0L;
    }
    static int injectPacket(long handle, byte[] packet) {
        return LOADED && handle != 0L && packet != null
                ? nativeInjectPacket(handle, packet) : -1;
    }
    static long[] packetStats(long handle) {
        return LOADED && handle != 0L
                ? nativePacketStats(handle) : new long[] {-1L, -1L, -1L};
    }
    static boolean closeSession(long handle) {
        return LOADED && handle != 0L && nativeCloseSession(handle);
    }
    static long[] protectionStats() {
        return LOADED ? nativeProtectionStats() : new long[] {0L, 0L};
    }

    static int validatePeerProfile(String config) { return LOADED ? nativeValidatePeerProfile(config) : 0; }
    static long createPeerSession(String name,String config) { return LOADED ? nativeCreatePeerSession(name,config) : -1L; }
    static long[] peerStats(long handle) { return LOADED && handle>0 ? nativePeerStats(handle) : new long[]{-1,-1,-1}; }
    static long createProbeSession(String name,String config,String local,String target,int port) {
        return LOADED?nativeCreateProbeSession(name,config,local,target,port):-1L;
    }
    static int pollProbePacket(long handle,byte[] output) {return LOADED?nativePollProbePacket(handle,output):-1;}
    private static native long nativeCreateProbeSession(String name,String config,String local,String target,int port);
    private static native int nativePollProbePacket(long handle,byte[] output);
    private static native int nativeValidatePeerProfile(String config);
    private static native long nativeCreatePeerSession(String name,String config);
    private static native long[] nativePeerStats(long handle);
    private static native boolean nativeSetVpnService(VpnService service);
    private static native boolean nativeClearVpnService(VpnService service);
    private static native long nativeCreateTestSession(String name);
    private static native long nativeCreatePacketTestSession(String name, String allowedIp);
    private static native int nativeInjectPacket(long handle, byte[] packet);
    private static native long[] nativePacketStats(long handle);
    private static native boolean nativeCloseSession(long handle);
    private static native long[] nativeProtectionStats();
}
