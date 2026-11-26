package com.yooshastan.wonheeproxy;

import android.net.Network;
import android.net.VpnService;
import android.os.SystemClock;
import java.io.*;
import java.net.*;
import java.security.SecureRandom;
import java.util.*;
import javax.net.ssl.*;

// Explicit pre-tunnel DNS-over-TLS. Never use Android/system DNS, never retry plaintext.
final class NativeEndpointBootstrap {
    private final VpnService service;
    private final Network network;
    private final SecureRandom random=new SecureRandom();
    private final Map<String,Cache> cache=new HashMap<>();
    private final String[] status={"numeric/override","numeric/override","numeric/override"};
    private boolean closed;
    private Socket active;
    private final long deadline=SystemClock.elapsedRealtime()+45000L;
    private static final class Cache {
        final String ip;final long expiry;
        Cache(String ip,long expiry){this.ip=ip;this.expiry=expiry;}
    }
    NativeEndpointBootstrap(VpnService service,Network network){this.service=service;this.network=network;}
    private int timeout()throws IOException{
        long left=deadline-SystemClock.elapsedRealtime();if(left<=0)throw new IOException();
        return (int)Math.min(5000L,left);
    }
    private synchronized void track(Socket s)throws IOException{
        if(closed){s.close();throw new IOException();}active=s;
    }
    synchronized void close(){
        closed=true;if(active!=null)try{active.close();}catch(IOException ignored){}active=null;
    }
    String summary(){return "BOOTSTRAP — Exit A="+status[0]+"; Exit B="+status[1]+"; Home="+status[2]+"; plaintext fallback=0";}
    String resolve(String name,int slot)throws Exception{
        String host=NativeEndpointDnsMessage.host(name);
        Cache hit=cache.get(host);long now=SystemClock.elapsedRealtime();
        if(hit!=null&&hit.expiry>now){status[slot]="secure-cache";return hit.ip;}
        NativeEndpointDnsMessage.Answer a=query(host,1);
        if(a==null)a=query(host,28);
        if(a==null)throw new IOException();
        if(a.ttl>0)cache.put(host,new Cache(a.ip,SystemClock.elapsedRealtime()+a.ttl*1000L));
        status[slot]="authenticated-DoT";
        return a.ip;
    }
    private NativeEndpointDnsMessage.Answer query(String host,int type)throws Exception{
        int id=random.nextInt(65536);
        byte[] q=NativeEndpointDnsMessage.query(host,id,type);
        try(Socket raw=new Socket()){
            track(raw);
            if(!service.protect(raw))throw new IOException();
            network.bindSocket(raw);
            raw.connect(new InetSocketAddress(InetAddress.getByAddress(new byte[]{1,1,1,1}),853),timeout());
            raw.setSoTimeout(timeout());
            SSLSocketFactory factory=(SSLSocketFactory)SSLSocketFactory.getDefault();
            try(SSLSocket tls=(SSLSocket)factory.createSocket(raw,"cloudflare-dns.com",853,true)){
                SSLParameters params=tls.getSSLParameters();
                params.setEndpointIdentificationAlgorithm("HTTPS");
                params.setServerNames(Collections.singletonList(new SNIHostName("cloudflare-dns.com")));
                tls.setSSLParameters(params);
                tls.setSoTimeout(timeout());tls.startHandshake();
                DataOutputStream out=new DataOutputStream(tls.getOutputStream());
                out.writeShort(q.length);out.write(q);out.flush();
                DataInputStream in=new DataInputStream(tls.getInputStream());
                tls.setSoTimeout(timeout());
                int n=in.readUnsignedShort();if(n<12||n>16384)throw new IOException();
                byte[] b=new byte[n];int read=0;
                while(read<n){tls.setSoTimeout(timeout());int got=in.read(b,read,n-read);if(got<1)throw new IOException();read+=got;}
                return NativeEndpointDnsMessage.parse(b,host,id,type);
            }
        }finally{synchronized(this){active=null;}}
    }
}
