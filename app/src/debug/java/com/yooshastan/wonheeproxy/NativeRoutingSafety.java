package com.yooshastan.wonheeproxy;

/** Pure, bounded preview safety rules; never opens a socket or chooses a fallback. */
final class NativeRoutingSafety {
    static final long BOOTSTRAP_BUDGET_MS=60000L, BOOTSTRAP_IO_MS=7500L;
    static final long ISOLATION_MS=90000L;
    static boolean retryBootstrap(String code,int attempt,long remaining,boolean stopped){
        return !stopped&&attempt==0&&remaining>=1000L&&
            ("connect/CONNECT".equals(code)||"connect/TIMEOUT".equals(code)||"tls-handshake/TIMEOUT".equals(code)||
             "doh-read/TIMEOUT".equals(code)||"dot-read/TIMEOUT".equals(code));
    }
    static boolean isolationAllowed(int role,int count,int dnsRole){
        return role>=0&&role<count&&role!=dnsRole;
    }
    static boolean isolationAllowed(int role,int count,int dnsRole,boolean splitDns){
        return role>=0&&role<count&&(splitDns||role!=dnsRole);
    }
    static boolean held(int role,int testRole,long now,long until){
        return role>=0&&role==testRole&&now<until;
    }
    private NativeRoutingSafety(){}
}
