package com.yooshastan.wonheeproxy;

import java.util.*;

// Immutable snapshot and bounded tuple ownership. No Android or network calls.
final class NativeAppRoutingPolicy {
    static final int DROP=-1,A=0,B=1,HOME=2,INHERIT=3;
    static final int TUN=MultiTunnelIpv4Rewriter.parseIpv4("10.253.0.1");
    static final int DNS=MultiTunnelIpv4Rewriter.parseIpv4("1.1.1.1");
    static final int MAX_FLOWS=4096;
    static final int[][] SELECTORS={{6,80},{6,443},{17,443},{6,53},{17,53},{6,853},{17,853},{6,22},{6,110},{6,995},{6,143},{6,993},{6,465},{6,587}};
    static final String[] SELECTOR_NAMES={"HTTP · TCP 80","HTTPS · TCP 443","QUIC-like · UDP 443","DNS · TCP 53","DNS · UDP 53","DoT-like · TCP 853","DoQ-like · UDP 853","SSH · TCP 22","POP3 · TCP 110","POP3 TLS · TCP 995","IMAP · TCP 143","IMAP TLS · TCP 993","SMTP TLS · TCP 465","SMTP submission · TCP 587"};
    static final class App {
        final int category,role;
        App(int category,int role){
            if(!AppUseCategories.valid(category)||!choice(role))throw new IllegalArgumentException();
            this.category=category;this.role=role;
        }
        boolean same(App other){return other!=null&&category==other.category&&role==other.role;}
    }
    static final class Prefix {
        final int network,bits,mask;
        Prefix(String value){
            if(value==null)throw new IllegalArgumentException();
            String[] parts=value.split("/",-1);if(parts.length!=2||!parts[1].matches("[0-9]{1,2}"))throw new IllegalArgumentException();
            network=MultiTunnelIpv4Rewriter.parseIpv4(parts[0]);bits=Integer.parseInt(parts[1]);
            if(bits<8||bits>32)throw new IllegalArgumentException();
            mask=bits==32?-1:-1<<(32-bits);
            if((network&mask)!=network||!privateIp(network)||(network>>>24)==10&&bits<8||((network&0xfff00000)==0xac100000&&bits<12)||((network&0xffff0000)==0xc0a80000&&bits<16))
                throw new IllegalArgumentException();
            if(contains(TUN))throw new IllegalArgumentException();
        }
        boolean contains(int ip){return (ip&mask)==network;}
    }
    static boolean privateIp(int ip){return (ip>>>24)==10||(ip&0xfff00000)==0xac100000||(ip&0xffff0000)==0xc0a80000;}
    static boolean publicIp(int ip){
        int first=ip>>>24;
        return first>0&&first<224&&first!=127&&!privateIp(ip)&&(ip&0xffff0000)!=0xa9fe0000&&(ip&0xffc00000)!=0x64400000
            &&(ip&0xffffff00)!=0xc0000000&&(ip&0xffffff00)!=0xc0000200&&(ip&0xfffe0000)!=0xc6120000&&(ip&0xffffff00)!=0xc6336400&&(ip&0xffffff00)!=0xcb007100;
    }
    static boolean choice(int r){return r==DROP||r==A||r==B||r==INHERIT;}
    final Prefix home;
    final int fallback;
    final int[] categories,protocols;
    NativeAppRoutingPolicy(Prefix home,int fallback,int[] categories,int[] protocols){
        if(fallback!=A&&fallback!=B||categories.length!=AppUseCategories.LABELS.length||protocols.length!=SELECTORS.length)throw new IllegalArgumentException();
        this.home=home;this.fallback=fallback;this.categories=categories.clone();this.protocols=protocols.clone();
        for(int r:categories)if(!choice(r))throw new IllegalArgumentException();
        for(int r:protocols)if(!choice(r))throw new IllegalArgumentException();
    }
    int choose(Key key,App app,boolean systemDns){
        // Only explicitly configured private Home ranges can reach Home.
        if(app==null&&(!systemDns||!key.fixedDns()))return DROP;
        if(privateIp(key.remote))return app!=null&&home!=null&&home.contains(key.remote)?HOME:DROP;
        if(!publicIp(key.remote))return DROP;
        // Explicit public-traffic blocks are not overridden by a port route.
        if(app!=null&&(app.role==DROP||app.role==INHERIT&&categories[app.category]==DROP))return DROP;
        for(int i=0;i<SELECTORS.length;i++)if(SELECTORS[i][0]==key.proto&&SELECTORS[i][1]==key.remotePort&&protocols[i]!=INHERIT)return protocols[i];
        if(app==null)return fallback; // fixed resolver only, no other unidentified traffic
        if(app.role!=INHERIT)return app.role;
        int role=categories[app.category];return role==INHERIT?fallback:role;
    }
    static final class Key {
        final int remote,localPort,remotePort,proto;
        Key(int remote,int localPort,int remotePort,int proto){this.remote=remote;this.localPort=localPort;this.remotePort=remotePort;this.proto=proto;}
        @Override public int hashCode(){return Objects.hash(remote,localPort,remotePort,proto);}
        @Override public boolean equals(Object o){if(!(o instanceof Key))return false;Key k=(Key)o;return remote==k.remote&&localPort==k.localPort&&remotePort==k.remotePort&&proto==k.proto;}
        boolean fixedDns(){return remote==DNS&&remotePort==53;}
    }
    static int u16(byte[] b,int i){return ((b[i]&255)<<8)|(b[i+1]&255);}
    static int ip(byte[] b,int i){return (u16(b,i)<<16)|u16(b,i+2);}
    static Key key(byte[] b,boolean reply){
        if(b==null||b.length<28||b.length>1280||b[0]!=0x45||u16(b,2)!=b.length||(u16(b,6)&0xbfff)!=0)return null;
        int proto=b[9]&255;
        if(proto==6){if(b.length<40||((b[32]&255)>>>4)<5||20+((b[32]&255)>>>4)*4>b.length)return null;}
        else if(proto==17){if(u16(b,24)!=b.length-20)return null;}else return null;
        int local=reply?ip(b,16):ip(b,12),remote=reply?ip(b,12):ip(b,16);
        int lp=u16(b,reply?22:20),rp=u16(b,reply?20:22);
        if(local!=TUN||remote==TUN||lp==0||rp==0)return null;
        return new Key(remote,lp,rp,proto);
    }
    static boolean syn(byte[] b){return b.length>=40&&b[9]==6&&(b[33]&0x17)==2;}
    static final class Owner {
        final int uid,role;long expiry;
        Owner(int uid,int role,long expiry){this.uid=uid;this.role=role;this.expiry=expiry;}
    }
    static final class Ledger {
        final Map<Key,Owner> entries=new HashMap<>();
        long sweepAt;
        Owner get(Key k,long now){
            Owner owner=entries.get(k);
            if(owner!=null&&owner.expiry<=now){entries.remove(k);return null;}return owner;
        }
        void sweep(long now){
            if(now<sweepAt)return;
            entries.entrySet().removeIf(e->e.getValue().expiry<=now);sweepAt=now+1000;
        }
        static long ttl(Key k){return k.proto==6?300000L:60000L;}
        Owner admit(Key k,boolean syn,int uid,int role,long now){
            sweep(now);
            Owner prior=get(k,now);
            if(prior!=null){
                if(prior.uid!=uid||prior.role!=role)return null;
                prior.expiry=now+ttl(k);return prior;
            }
            if(role<0||role>HOME||k.proto==6&&!syn||entries.size()>=MAX_FLOWS)return null;
            Owner owner=new Owner(uid,role,now+ttl(k));entries.put(k,owner);return owner;
        }
        boolean reply(Key k,int role,long now){Owner o=get(k,now);return o!=null&&o.role==role;}
    }
}
