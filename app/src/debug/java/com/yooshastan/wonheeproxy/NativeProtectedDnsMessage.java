package com.yooshastan.wonheeproxy;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

// Bounded DNS wire handling for a single UDP question, no domain logging.
final class NativeProtectedDnsMessage {
    static final int MAX_DNS=1252, MAX_REPLY=16384;
    static final int DNS_IP=0x01010101;
    static int u16(byte[] a,int i){return ((a[i]&255)<<8)|(a[i+1]&255);}
    static void put(byte[] a,int i,int v){a[i]=(byte)(v>>>8);a[i+1]=(byte)v;}
    static final class Question {
        final String name;final int type,clazz,end;
        Question(String n,int t,int c,int e){name=n;type=t;clazz=c;end=e;}
        boolean same(Question q){return name.equals(q.name)&&type==q.type&&clazz==q.clazz;}
    }
    static Question question(byte[] b)throws IOException{
        if(b.length<17||u16(b,4)!=1)throw new IOException("question count");
        int pos=12;StringBuilder n=new StringBuilder();
        while(true){
            if(pos>=b.length)throw new IOException("name length");
            int count=b[pos++]&255;if(count==0)break;
            if(count>63||pos+count>b.length||n.length()+count+1>254)throw new IOException("label length");
            if(n.length()>0)n.append('.');
            for(int i=0;i<count;i++){
                int c=b[pos++]&255;if(c<33||c>126||c=='.')throw new IOException("label syntax");
                n.append((char)c);
            }
        }
        if(n.length()==0||pos+4>b.length)throw new IOException("question missing");
        return new Question(n.toString().toLowerCase(Locale.ROOT),u16(b,pos),u16(b,pos+2),pos+4);
    }
    static byte[] normalize(byte[] b)throws IOException{
        if(b.length>MAX_DNS||b.length<12||(u16(b,2)&0xf800)!=0||u16(b,6)!=0||u16(b,8)!=0)throw new IOException("query shape");
        Question q=question(b);if(q.clazz!=1||q.type==0)throw new IOException("query class");
        // Strip EDNS options (including ECS) and unrelated additional data.
        byte[] out=Arrays.copyOf(b,q.end);put(out,2,u16(b,2)&0x0110);put(out,10,0);return out;
    }
    // Respect a single well-formed EDNS OPT advertised receive size, otherwise
    // use the classic 512-byte bound. Never exceed the captured IPv4 MTU.
    static int udpLimit(byte[] raw){
        try{
            Question q=question(raw);int p=q.end;
            if(u16(raw,6)!=0||u16(raw,8)!=0||u16(raw,10)!=1||p+11>raw.length||raw[p]!=0||u16(raw,p+1)!=41||p+11+u16(raw,p+9)!=raw.length)return 512;
            return Math.max(512,Math.min(MAX_DNS,u16(raw,p+3)));
        }catch(IOException|RuntimeException e){return 512;}
    }
    static boolean blocked(String name,Set<String> domains){
        for(String at=name;;){
            if(domains.contains(at))return true;
            int dot=at.indexOf('.');if(dot<0)return false;at=at.substring(dot+1);
        }
    }
    static byte[] error(byte[] query,int code,boolean truncated)throws IOException{
        Question q=question(query);byte[] r=Arrays.copyOf(query,q.end);
        put(r,2,0x8080|(u16(query,2)&0x0110)|(truncated?0x0200:0)|code);
        put(r,6,0);put(r,8,0);put(r,10,0);return r;
    }
    static byte[] validate(byte[] q,byte[] answer)throws IOException{
        byte[] checked=validateFull(q,answer);
        if(checked.length>MAX_DNS)return error(q,0,true);
        return checked;
    }
    static byte[] validateFull(byte[] q,byte[] answer)throws IOException{
        if(answer.length<12||answer.length>MAX_REPLY||u16(q,0)!=u16(answer,0)||(u16(answer,2)&0xf800)!=0x8000||!question(q).same(question(answer)))throw new IOException("response mismatch");
        return answer;
    }
    // IPv4 UDP reply from the configured virtual resolver, no external UDP.
    static byte[] reply(byte[] request,byte[] dns)throws IOException{
        if(request.length<28||request[0]!=0x45||request[9]!=17||dns.length>MAX_DNS)throw new IOException();
        byte[] out=new byte[28+dns.length];out[0]=0x45;put(out,2,out.length);out[8]=64;out[9]=17;
        System.arraycopy(request,16,out,12,4);System.arraycopy(request,12,out,16,4);
        put(out,20,u16(request,22));put(out,22,u16(request,20));put(out,24,8+dns.length);
        System.arraycopy(dns,0,out,28,dns.length);
        int sum=0;for(int i=0;i<20;i+=2)sum+=u16(out,i);
        while((sum>>>16)!=0)sum=(sum&65535)+(sum>>>16);
        put(out,10,(~sum)&65535);
        // UDP checksum zero is explicitly permitted in IPv4.
        return out;
    }
}
