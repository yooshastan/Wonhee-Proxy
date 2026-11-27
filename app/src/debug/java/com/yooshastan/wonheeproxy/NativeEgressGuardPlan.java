package com.yooshastan.wonheeproxy;

import java.util.*;

/** Narrow preview guard, deliberately separate from the quarantined legacy kernel guard.
 * All exemptions RETURN to existing OUTPUT policy, never ACCEPT.
 * Does not promise whole-device lockdown. */
final class NativeEgressGuardPlan implements NativeEgressGuardRuntime.OwnedPlan {
    static final int DNS_IPV6=1, STRICT_IP=2;
    final String token, tun;
    final int uid, mode, validationPort;
    final boolean localDiscovery;
    final List<String> endpoints;
    NativeEgressGuardPlan(String token,String tun,int uid,int mode,boolean localDiscovery,List<String> endpoints){
        this(token,tun,uid,mode,localDiscovery,endpoints,0);
    }
    NativeEgressGuardPlan(String token,String tun,int uid,int mode,boolean localDiscovery,List<String> endpoints,int validationPort){
        if(token==null||!token.matches("[0-9a-f]{12}")||tun==null||!tun.matches("tun[0-9]{1,8}")
            ||uid<10000||(mode!=DNS_IPV6&&mode!=STRICT_IP)||endpoints==null||endpoints.size()<2||endpoints.size()>3)
            throw new IllegalArgumentException("INVALID_EGRESS_PLAN");
        if(validationPort!=0&&(validationPort<1024||validationPort>65535||mode!=DNS_IPV6))throw new IllegalArgumentException("INVALID_VALIDATION_PORT");
        this.validationPort=validationPort;
        this.token=token;this.tun=tun;this.uid=uid;this.mode=mode;this.localDiscovery=localDiscovery;
        List<String> checked=new ArrayList<>();
        for(String value:endpoints){
            RootTcpProbeTarget t=RootTcpProbeTarget.parse(value);
            if(checked.contains(t.label()))throw new IllegalArgumentException("DUPLICATE_ENDPOINT");
            checked.add(t.label());
        }
        this.endpoints=Collections.unmodifiableList(checked);
    }
    static List<String> endpoints(String[] configs){
        List<String> endpoints=new ArrayList<>();
        for(String config:configs){
            String found=null;
            for(String line:config.split("\\n"))if(line.startsWith("Endpoint = ")){
                if(found!=null)throw new IllegalArgumentException("MULTIPLE_ENDPOINTS");
                found=RootTcpProbeTarget.parse(line.substring("Endpoint = ".length())).label();
            }
            if(found==null)throw new IllegalArgumentException("MISSING_ENDPOINT");
            endpoints.add(found);
        }
        return endpoints;
    }
    public int[] families(){return new int[]{4,6};}
    NativeValidationDnsPlan validationPlan(){return validationPort==0?null:new NativeValidationDnsPlan(token,validationPort);}
    public String chain(int family){return "WNE"+family+"_"+token;}
    public String tag(int family){return "WNE_"+token+"_"+family;}
    public String prefix(int family){if(family!=4&&family!=6)throw new IllegalArgumentException();return (family==4?"iptables":"ip6tables")+" -w 3 -t filter";}
    public String anchor(int family){return "-m comment --comment "+tag(family)+"_anchor -j "+chain(family);}
    public List<String> rules(int family){
        List<String> base=new ArrayList<>();
        if(family==4&&validationPort!=0)for(String proto:new String[]{"udp","tcp"}){
            String local="-o lo -d 127.0.0.1 -p "+proto+" --dport "+validationPort;
            base.add(local+" -m owner --uid-owner "+NativeValidationDnsPolicy.NETWORK_STACK_UID+" -j RETURN");
            base.add(local+" -j DROP");
        }
        base.add("-o lo -j RETURN");
        base.add("-o "+tun+" -j RETURN");
        // Preserve exact authenticated-session transport destinations, not a broad UID exception.
        for(String endpoint:endpoints){
            RootTcpProbeTarget t=RootTcpProbeTarget.parse(endpoint);
            if(t.family==family)base.add("-p udp -d "+t.address+" --dport "+t.port+" -m owner --uid-owner "+uid+" -j RETURN");
        }
        // Explicit local control only. These are not general LAN allowances.
        if(family==4){
            base.add("-p udp --sport 68 --dport 67 -d 255.255.255.255 -j RETURN");
        }else{
            for(int type:new int[]{130,131,132,133,135,136,143}){
                base.add("-p ipv6-icmp --icmpv6-type "+type+" -d ff02::/16 -j RETURN");
                if(type==135||type==136)base.add("-p ipv6-icmp --icmpv6-type "+type+" -d fe80::/10 -j RETURN");
            }
            base.add("-p udp --sport 546 --dport 547 -d ff02::1:2 -j RETURN");
            base.add("-p udp --sport 546 --dport 547 -d fe80::/10 -j RETURN");
        }
        if(localDiscovery){
            base.add("-p udp -d "+(family==4?"224.0.0.251":"ff02::fb")+" --dport 5353 -j RETURN");
            base.add("-p udp -d "+(family==4?"239.255.255.250":"ff02::c")+" --dport 1900 -j RETURN");
        }else{
            base.add("-p udp --dport 5353 -j DROP");
            base.add("-p udp --dport 1900 -j DROP");
        }
        for(String proto:new String[]{"tcp","udp"})for(int port:new int[]{53,853})
            base.add("-p "+proto+" --dport "+port+" -j DROP");
        // In the narrow mode all remaining IPv4 is unchanged. IPv6 direct data is denied.
        base.add(family==6||mode==STRICT_IP?"-j DROP":"-j RETURN");
        List<String> result=new ArrayList<>();
        for(int i=0;i<base.size();i++){
            String r=base.get(i);int j=r.lastIndexOf("-j ");
            result.add(r.substring(0,j)+"-m comment --comment "+tag(family)+"_"+i+" "+r.substring(j));
        }
        return result;
    }
    String encode(){return token+"\n"+tun+"\n"+uid+"\n"+mode+"\n"+(localDiscovery?"1":"0")+"\n"+String.join("\n",endpoints)+(validationPort==0?"":"\nvalidation="+validationPort);}
    static NativeEgressGuardPlan decode(String data){
        if(data==null||data.length()>1024)throw new IllegalArgumentException("INVALID_EGRESS_JOURNAL");
        String[] p=data.split("\\n",-1);
        if(p.length<7||p.length>9||(!p[4].equals("0")&&!p[4].equals("1")))throw new IllegalArgumentException("INVALID_EGRESS_JOURNAL");
        int end=p.length,port=0;
        if(p[end-1].startsWith("validation=")){
            port=Integer.parseInt(p[--end].substring("validation=".length()));
            if(port<1024||port>65535)throw new IllegalArgumentException("INVALID_VALIDATION_PORT");
        }
        return new NativeEgressGuardPlan(p[0],p[1],Integer.parseInt(p[2]),Integer.parseInt(p[3]),p[4].equals("1"),Arrays.asList(p).subList(5,end),port);
    }
}
