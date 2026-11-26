package com.yooshastan.wonheeproxy;
final class NativeDnsTransportPolicy {
    static final int DOT=0,DOQ=1,DOH3=2;
    static final String[] LABELS={"DNS over TLS (DoT)","DNS over QUIC (DoQ)","DNS over HTTP/3 (DoH3)"};
    static boolean supports(int provider,int mode){
        return provider>=0&&provider<4&&(mode==DOT||mode==DOQ&&(provider==1||provider==2)||mode==DOH3&&(provider==0||provider==1||provider==2));
    }
    static int port(int mode){return mode==DOH3?443:853;}
    static int protocol(int mode){return mode==DOT?6:17;}
    private NativeDnsTransportPolicy(){}
}
