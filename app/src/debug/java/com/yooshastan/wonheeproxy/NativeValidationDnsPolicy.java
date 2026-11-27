package com.yooshastan.wonheeproxy;

import java.io.IOException;
import java.util.Arrays;

/** Only the exact validation names observed in the device's NetworkMonitor config.
 * No arbitrary system DNS, suffix matching, EDNS or user-controlled upstream ID. */
final class NativeValidationDnsPolicy {
    static final int NETWORK_STACK_UID=1073;
    static byte[] canonical(byte[] request,int upstreamId)throws IOException{
        byte[] normalized=NativeProtectedDnsMessage.normalize(request);
        NativeProtectedDnsMessage.Question q=NativeProtectedDnsMessage.question(normalized);
        if(!("www.google.com".equals(q.name)||"connectivitycheck.gstatic.com".equals(q.name)||"play.googleapis.com".equals(q.name))
            ||(q.type!=1&&q.type!=28))throw new IOException("validation question refused");
        byte[] out=NativeProtectedDnsMessage.testQuery(q.name,upstreamId);
        NativeProtectedDnsMessage.put(out,out.length-4,q.type);
        return out;
    }
    static byte[] response(byte[] request,byte[] canonical,byte[] answer,boolean udp)throws IOException{
        byte[] checked=NativeProtectedDnsMessage.validateFull(canonical,answer).clone();
        NativeProtectedDnsMessage.Question original=NativeProtectedDnsMessage.question(request);
        NativeProtectedDnsMessage.Question returned=NativeProtectedDnsMessage.question(checked);
        if(original.end!=returned.end)throw new IOException("question size changed");
        // Preserve the client's question case and transaction ID locally.
        System.arraycopy(request,12,checked,12,original.end-12);
        NativeProtectedDnsMessage.put(checked,0,NativeProtectedDnsMessage.u16(request,0));
        if(udp&&checked.length>NativeProtectedDnsMessage.udpLimit(request))
            return NativeProtectedDnsMessage.error(request,0,true);
        return checked;
    }
    private NativeValidationDnsPolicy(){}
}
