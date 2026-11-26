package com.yooshastan.wonheeproxy;

import java.io.*;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;

// Bounded DNS wire codec. No network or Android dependencies.
final class NativeEndpointDnsMessage {
    static final class Answer {
        final String ip; final long ttl;
        Answer(String ip,long ttl){this.ip=ip;this.ttl=ttl;}
    }
    static String host(String value) throws IOException {
        if(value==null)throw new IOException();
        String h=value.toLowerCase(Locale.ROOT);
        if(h.endsWith("."))h=h.substring(0,h.length()-1);
        if(h.length()>253||h.isEmpty())throw new IOException();
        for(String label:h.split("\\.",-1))if(!label.matches("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"))throw new IOException();
        return h;
    }
    static byte[] query(String name,int id,int type) throws IOException {
        if(type!=1&&type!=28)throw new IOException();
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();
        DataOutputStream out=new DataOutputStream(bytes);
        out.writeShort(id);out.writeShort(0x0100);out.writeShort(1);
        out.writeShort(0);out.writeShort(0);out.writeShort(0);
        for(String label:host(name).split("\\.")){
            byte[] b=label.getBytes(StandardCharsets.US_ASCII);out.writeByte(b.length);out.write(b);
        }
        out.writeByte(0);out.writeShort(type);out.writeShort(1);return bytes.toByteArray();
    }
    private static int u16(byte[] b,int i)throws IOException{
        if(i<0||i+2>b.length)throw new IOException();return ((b[i]&255)<<8)|(b[i+1]&255);
    }
    private static String name(byte[] b,int[] cursor)throws IOException{
        int i=cursor[0],jumps=0;boolean jumped=false;StringBuilder s=new StringBuilder();
        while(true){
            if(i>=b.length||++jumps>128)throw new IOException();
            int n=b[i++]&255;
            if(n==0){if(!jumped)cursor[0]=i;return host(s.toString());}
            if((n&192)==192){
                if(i>=b.length)throw new IOException();
                int dest=((n&63)<<8)|(b[i++]&255);
                if(dest>=i-2||dest<12)throw new IOException();
                if(!jumped){cursor[0]=i;jumped=true;}i=dest;continue;
            }
            if(n>63||i+n>b.length||s.length()+n+1>254)throw new IOException();
            if(s.length()>0)s.append('.');
            s.append(new String(b,i,n,StandardCharsets.US_ASCII));i+=n;
        }
    }
    static Answer parse(byte[] b,String hostname,int id,int type)throws IOException{
        String h=host(hostname);
        if(b.length<12||b.length>16384||u16(b,0)!=id)throw new IOException();
        int flags=u16(b,2),count=u16(b,6);
        if((flags&0xFA0F)!=0x8000||u16(b,4)!=1||count>128)throw new IOException();
        int[] cursor={12};
        if(!name(b,cursor).equals(h)||u16(b,cursor[0])!=type||u16(b,cursor[0]+2)!=1)throw new IOException();
        cursor[0]+=4;
        Map<String,String> aliases=new HashMap<>();
        Map<String,Long> aliasTtls=new HashMap<>();
        Map<String,Answer> answers=new HashMap<>();
        for(int j=0;j<count;j++){
            String owner=name(b,cursor);int i=cursor[0];
            int kind=u16(b,i),cls=u16(b,i+2),len=u16(b,i+8);
            long ttl=((long)u16(b,i+4)<<16)|u16(b,i+6);
            int data=i+10,end=data+len;if(end>b.length)throw new IOException();
            if(cls==1&&kind==5){
                int[] c={data};String target=name(b,c);
                if(c[0]!=end||aliases.putIfAbsent(owner,target)!=null)throw new IOException();
                aliasTtls.put(owner,ttl);
            }else if(cls==1&&kind==type&&len==(type==1?4:16)){
                InetAddress a=InetAddress.getByAddress(Arrays.copyOfRange(b,data,end));
                if(!a.isAnyLocalAddress()&&!a.isLoopbackAddress()&&!a.isMulticastAddress()&&!a.isLinkLocalAddress()&&
                   (type==1?a.getAddress().length==4:a.getAddress().length==16))
                    answers.putIfAbsent(owner,new Answer(a.getHostAddress(),ttl));
            }
            cursor[0]=end;
        }
        Set<String> seen=new HashSet<>();long ttl=3600;
        for(int j=0;j<16;j++){
            if(!seen.add(h))throw new IOException();
            if(aliases.containsKey(h)){
                if(answers.containsKey(h))throw new IOException();
                ttl=Math.min(ttl,aliasTtls.get(h));h=aliases.get(h);
            }else{
                Answer answer=answers.get(h);
                return answer==null?null:new Answer(answer.ip,Math.min(ttl,answer.ttl));
            }
        }
        throw new IOException();
    }
}
