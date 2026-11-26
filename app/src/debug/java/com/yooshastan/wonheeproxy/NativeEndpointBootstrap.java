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
    // Only fixed stage and error codes leave the resolver. Never log a hostname,
    // endpoint address, exception message, certificate, or profile.
    static final class Failure extends IOException {
        final String code;
        Failure(String code){super(code);this.code=code;}
    }
    private static String category(Exception e){
        if(e instanceof SSLPeerUnverifiedException)return "TLS_PEER_UNVERIFIED";
        if(e instanceof SSLHandshakeException)return "TLS_HANDSHAKE";
        if(e instanceof SSLException)return "TLS_IO";
        if(e instanceof SocketTimeoutException)return "TIMEOUT";
        if(e instanceof ConnectException)return "CONNECT";
        if(e instanceof NoRouteToHostException)return "NO_ROUTE";
        if(e instanceof SecurityException)return "SECURITY";
        if(e instanceof SocketException)return "SOCKET";
        if(e instanceof IOException)return "IO";
        return "VALIDATION";
    }
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
        final String host;
        try{host=NativeEndpointDnsMessage.host(name);}
        catch(IOException invalid){throw new Failure("HOST_SYNTAX");}
        Cache hit=cache.get(host);long now=SystemClock.elapsedRealtime();
        if(hit!=null&&hit.expiry>now){status[slot]="secure-cache";return hit.ip;}
        NativeEndpointDnsMessage.Answer a=query(host,1);
        if(a==null)a=query(host,28);
        if(a==null)throw new Failure("NO_USABLE_ANSWER");
        if(a.ttl>0)cache.put(host,new Cache(a.ip,SystemClock.elapsedRealtime()+a.ttl*1000L));
        status[slot]="authenticated-DoT";
        return a.ip;
    }
    String resolveTransferTarget()throws Exception{
        NativeEndpointDnsMessage.Answer answer=query("speed.cloudflare.com",1);
        if(answer==null)throw new Failure("TRANSFER_IPV4_MISSING");
        return answer.ip;
    }
    private NativeEndpointDnsMessage.Answer query(String host,int type)throws Exception{
        int id=random.nextInt(65536);
        byte[] q=NativeEndpointDnsMessage.query(host,id,type);
        String stage="socket-create";
        try(Socket raw=new Socket()){
            track(raw);
            // Android's protect(Socket) needs a valid descriptor. Explicitly
            // allocate one without transmitting or connecting to any host.
            stage="local-bind";
            raw.bind(new InetSocketAddress(0));
            stage="protect";
            if(!service.protect(raw))throw new Failure("PROTECT_REFUSED");
            stage="network-bind";
            network.bindSocket(raw);
            stage="connect";
            raw.connect(new InetSocketAddress(InetAddress.getByAddress(new byte[]{1,1,1,1}),853),timeout());
            raw.setSoTimeout(timeout());
            stage="tls-setup";
            SSLSocketFactory factory=(SSLSocketFactory)SSLSocketFactory.getDefault();
            try(SSLSocket tls=(SSLSocket)factory.createSocket(raw,"cloudflare-dns.com",853,true)){
                SSLParameters params=tls.getSSLParameters();
                params.setEndpointIdentificationAlgorithm("HTTPS");
                params.setServerNames(Collections.singletonList(new SNIHostName("cloudflare-dns.com")));
                tls.setSSLParameters(params);
                stage="tls-handshake";
                tls.setSoTimeout(timeout());tls.startHandshake();
                stage="dns-write";
                DataOutputStream out=new DataOutputStream(tls.getOutputStream());
                out.writeShort(q.length);out.write(q);out.flush();
                stage="dns-read";
                DataInputStream in=new DataInputStream(tls.getInputStream());
                tls.setSoTimeout(timeout());
                int n=in.readUnsignedShort();if(n<12||n>16384)throw new IOException();
                byte[] b=new byte[n];int read=0;
                while(read<n){tls.setSoTimeout(timeout());int got=in.read(b,read,n-read);if(got<1)throw new IOException();read+=got;}
                stage="dns-validate";
                return NativeEndpointDnsMessage.parse(b,host,id,type);
            }
        }catch(Failure failure){throw failure;}
        catch(Exception failure){throw new Failure(stage+"/"+category(failure));}
        finally{synchronized(this){active=null;}}
    }
}
