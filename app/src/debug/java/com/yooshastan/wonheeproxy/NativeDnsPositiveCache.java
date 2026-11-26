package com.yooshastan.wonheeproxy;
import java.io.IOException;
import java.util.*;

/** Per-session bounded, positive A/AAAA-only cache. No negative or alias caching. */
final class NativeDnsPositiveCache {
    private static final int LIMIT=512, TTL_LIMIT=120;
    private static final class Entry {
        final byte[] answer;final int[] offsets;final long stored,ttl;
        Entry(byte[] a,int[] o,long now,long ttl){answer=a;offsets=o;stored=now;this.ttl=ttl;}
    }
    private final LinkedHashMap<String,Entry> entries=new LinkedHashMap<>(32,0.75f,true);
    private static String key(byte[] q){
        // Exact normalized wire question, including case/flags; exclude transaction ID.
        return Base64.getEncoder().encodeToString(Arrays.copyOfRange(q,2,q.length));
    }
    private static int u16(byte[] a,int p){return NativeProtectedDnsMessage.u16(a,p);}
    private static long u32(byte[] a,int p){return ((long)u16(a,p)<<16)|u16(a,p+2);}
    private static void put32(byte[] a,int p,long n){NativeProtectedDnsMessage.put(a,p,(int)(n>>>16));NativeProtectedDnsMessage.put(a,p+2,(int)n);}
    synchronized byte[] get(byte[] query,long now){
        String k=key(query);Entry e=entries.get(k);if(e==null)return null;
        long elapsed=now-e.stored;
        if(elapsed<0||elapsed>=e.ttl*1000){entries.remove(k);return null;}
        // Round elapsed time up so cached records are never served past their TTL.
        long age=(elapsed+999)/1000;
        if(age>=e.ttl){entries.remove(k);return null;}
        byte[] out=e.answer.clone();out[0]=query[0];out[1]=query[1];
        for(int p:e.offsets)put32(out,p,Math.max(0,u32(out,p)-age));
        return out;
    }
    synchronized boolean put(byte[] query,byte[] answer,long now){
        try{
            NativeProtectedDnsMessage.Question q=NativeProtectedDnsMessage.question(query),a=NativeProtectedDnsMessage.question(answer);
            if(q.type!=1&&q.type!=28||q.clazz!=1||!q.same(a)||a.end!=q.end||!Arrays.equals(Arrays.copyOfRange(query,12,q.end),Arrays.copyOfRange(answer,12,a.end)))return false;
            if(NativeProtectedDnsMessage.validate(query,answer)!=answer||answer.length>NativeProtectedDnsMessage.MAX_DNS)return false;
            int flags=u16(answer,2),count=u16(answer,6);
            if((flags&0x020f)!=0||count<1||count>32||u16(answer,8)!=0||u16(answer,10)!=0)return false;
            byte[] copy=answer.clone();int[] offsets=new int[count];int pos=a.end;long ttl=TTL_LIMIT;
            for(int i=0;i<count;i++){
                // Conservative: only the exact question owner via compression pointer.
                if(pos+12>copy.length||u16(copy,pos)!=0xc00c||u16(copy,pos+2)!=q.type||u16(copy,pos+4)!=1)return false;
                int len=u16(copy,pos+10);if(len!=(q.type==1?4:16)||pos+12+len>copy.length)return false;
                long rrTtl=Math.min(TTL_LIMIT,u32(copy,pos+6));if(rrTtl==0)return false;
                offsets[i]=pos+6;put32(copy,pos+6,rrTtl);ttl=Math.min(ttl,rrTtl);pos+=12+len;
            }
            if(pos!=copy.length)return false;
            entries.put(key(query),new Entry(copy,offsets,now,ttl));
            while(entries.size()>LIMIT)entries.remove(entries.keySet().iterator().next());
            return true;
        }catch(IOException|RuntimeException malformed){return false;}
    }
    synchronized int size(){return entries.size();}
    synchronized void clear(){entries.clear();}
}
