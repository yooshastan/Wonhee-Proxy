package com.yooshastan.wonheeproxy;
import java.util.*;

/** Versioned WLAN-only local NAT redirect. No external DNS exception. */
final class NativeValidationDnsPlan implements NativeEgressGuardRuntime.OwnedPlan {
    final String token;
    final int port;
    final boolean dual,rootOwner;
    int owner(){return rootOwner?0:NativeValidationDnsPolicy.NETWORK_STACK_UID;}
    NativeValidationDnsPlan(String token,int port){
        this(token,port,false);
    }
    NativeValidationDnsPlan(String token,int port,boolean dual){
        this(token,port,dual,dual);
    }
    NativeValidationDnsPlan(String token,int port,boolean dual,boolean rootOwner){
        if(dual&&!rootOwner)throw new IllegalArgumentException("INVALID_DUAL_OWNER");
        this.dual=dual;this.rootOwner=rootOwner;
        if(token==null||!token.matches("[0-9a-f]{12}")||port<1024||port>65535)throw new IllegalArgumentException("INVALID_VALIDATION_PLAN");
        this.token=token;this.port=port;
    }
    public int[] families(){return dual?new int[]{4,6}:new int[]{4};}
    public String chain(int f){if(f!=4&&!(dual&&f==6))throw new IllegalArgumentException();return "WNV"+f+"_"+token;}
    public String tag(int f){if(f!=4&&!(dual&&f==6))throw new IllegalArgumentException();return "WNV_"+token+"_"+f;}
    public String prefix(int f){if(f!=4&&!(dual&&f==6))throw new IllegalArgumentException();return (f==4?"iptables":"ip6tables")+" -w 3 -t nat";}
    public String anchor(int f){return "-m comment --comment "+tag(f)+"_anchor -j "+chain(f);}
    public List<String> rules(int f){
        List<String> out=new ArrayList<>();
        for(String proto:new String[]{"udp","tcp"})
            out.add("-o wlan0 -p "+proto+" --dport 53 -m owner --uid-owner "+owner()
                +" -m comment --comment "+tag(f)+"_"+out.size()+" -j REDIRECT --to-ports "+port);
        return out;
    }
}
