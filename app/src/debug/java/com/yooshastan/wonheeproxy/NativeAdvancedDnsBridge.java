package com.yooshastan.wonheeproxy;
final class NativeAdvancedDnsBridge {
    private NativeAdvancedDnsBridge(){}
    static native long createQuic(int provider,int mode,int alternate,byte[] roots);
    static native void closeQuic(long handle);
    static native int exchangeQuic(long handle,int fd,byte[] query,byte[] answer,long[] metrics);
    static native long createTcp();
    static native void closeTcp(long handle);
    static native int feedTcp(long handle,byte[] packet);
    static native int pollTcp(long handle,int kind,byte[] output);
    static native int answerTcp(long handle,long token,byte[] answer);
}
