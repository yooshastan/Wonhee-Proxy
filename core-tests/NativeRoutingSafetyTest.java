package com.yooshastan.wonheeproxy;
public final class NativeRoutingSafetyTest {
    static void check(boolean v){if(!v)throw new AssertionError();}
    public static void main(String[] args){
        check(NativeRoutingSafety.retryBootstrap("tls-handshake/TIMEOUT",0,10000,false));
        check(NativeRoutingSafety.retryBootstrap("connect/TIMEOUT",0,10000,false));
        check(NativeRoutingSafety.retryBootstrap("connect/CONNECT",0,10000,false));
        check(NativeRoutingSafety.retryBootstrap("doh-read/TIMEOUT",0,10000,false));
        check(!NativeRoutingSafety.retryBootstrap("tls-handshake/TLS_HANDSHAKE",0,10000,false));
        check(!NativeRoutingSafety.retryBootstrap("tls-handshake/TLS_PEER_UNVERIFIED",0,10000,false));
        check(!NativeRoutingSafety.retryBootstrap("dns-validate/IO",0,10000,false));
        check(!NativeRoutingSafety.retryBootstrap("PROTECT_REFUSED",0,10000,false));
        check(!NativeRoutingSafety.retryBootstrap("tls-handshake/TIMEOUT",1,10000,false));
        check(!NativeRoutingSafety.retryBootstrap("tls-handshake/TIMEOUT",0,999,false));
        check(!NativeRoutingSafety.retryBootstrap("tls-handshake/TIMEOUT",0,10000,true));
        check(NativeRoutingSafety.isolationAllowed(1,3,0));
        check(NativeRoutingSafety.isolationAllowed(2,3,0));
        check(!NativeRoutingSafety.isolationAllowed(0,3,0));
        check(NativeRoutingSafety.isolationAllowed(0,3,0,true));
        check(!NativeRoutingSafety.isolationAllowed(0,3,0,false));
        check(!NativeRoutingSafety.isolationAllowed(2,2,0));
        check(NativeRoutingSafety.held(1,1,1,30000));
        check(!NativeRoutingSafety.held(0,1,1,30000));
        check(!NativeRoutingSafety.held(1,1,30000,30000));
        System.out.println("Bounded bootstrap retry and isolation safety PASS");
    }
}
