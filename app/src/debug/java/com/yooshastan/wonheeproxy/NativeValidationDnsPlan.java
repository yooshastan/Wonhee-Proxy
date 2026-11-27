package com.yooshastan.wonheeproxy;
import java.util.*;

/** IPv4-only, WLAN-only NAT redirect. IPv6 DNS remains blocked. No ACCEPT rule. */
final class NativeValidationDnsPlan implements NativeEgressGuardRuntime.OwnedPlan {
    final String token;
    final int port;
    NativeValidationDnsPlan(String token,int port){
        if(token==null||!token.matches("[0-9a-f]{12}")||port<1024||port>65535)throw new IllegalArgumentException("INVALID_VALIDATION_PLAN");
        this.token=token;this.port=port;
    }
    public int[] families(){return new int[]{4};}
    public String chain(int f){if(f!=4)throw new IllegalArgumentException();return "WNV4_"+token;}
    public String tag(int f){if(f!=4)throw new IllegalArgumentException();return "WNV_"+token+"_4";}
    public String prefix(int f){if(f!=4)throw new IllegalArgumentException();return "iptables -w 3 -t nat";}
    public String anchor(int f){return "-m comment --comment "+tag(f)+"_anchor -j "+chain(f);}
    public List<String> rules(int f){
        List<String> out=new ArrayList<>();
        for(String proto:new String[]{"udp","tcp"})
            out.add("-o wlan0 -p "+proto+" --dport 53 -m owner --uid-owner "+NativeValidationDnsPolicy.NETWORK_STACK_UID
                +" -m comment --comment "+tag(f)+"_"+out.size()+" -j REDIRECT --to-ports "+port);
        return out;
    }
}
