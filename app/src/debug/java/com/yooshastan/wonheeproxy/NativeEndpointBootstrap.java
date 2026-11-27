package com.yooshastan.wonheeproxy;

import android.net.Network;
import android.net.VpnService;
import android.os.SystemClock;
import java.io.*;
import java.net.*;
import java.util.*;
import javax.net.ssl.*;

// Explicit pre-tunnel DNS-over-HTTPS or DNS-over-TLS; fixed numeric provider addresses. Never use Android/system DNS, never retry plaintext.
final class NativeEndpointBootstrap {
    private final VpnService service;
    private final Network network;
    static final String[] OPTIONS={"Cloudflare DoH · TCP 443","Cloudflare DoT · TCP 853","Quad9 DoH · TCP 443","Quad9 DoT · TCP 853","AdGuard DoH · TCP 443","AdGuard DoT · TCP 853"};
    private static final String[] HOSTS={"cloudflare-dns.com","dns.quad9.net","dns.adguard-dns.com"};
    private static final byte[][] IPS={{1,1,1,1},{9,9,9,9},{94,(byte)140,14,14}};
    private final String tlsHost;
    private final byte[] resolverIp;
    private final int port;
    static boolean validOption(int n){return n>=0&&n<OPTIONS.length;}
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
    private final long deadline=SystemClock.elapsedRealtime()+NativeRoutingSafety.BOOTSTRAP_BUDGET_MS;
    private int retries;
    private static final class Cache {
        final String ip;final long expiry;
        Cache(String ip,long expiry){this.ip=ip;this.expiry=expiry;}
    }
    NativeEndpointBootstrap(VpnService service,Network network){this(service,network,0);}
    NativeEndpointBootstrap(VpnService service,Network network,int option){if(!validOption(option))throw new IllegalArgumentException();this.service=service;this.network=network;tlsHost=HOSTS[option/2];resolverIp=IPS[option/2].clone();port=option%2==0?443:853;}
    private int timeout()throws IOException{
        long left=deadline-SystemClock.elapsedRealtime();if(left<=0)throw new IOException();
        return (int)Math.min(NativeRoutingSafety.BOOTSTRAP_IO_MS,left);
    }
    private synchronized void track(Socket s)throws IOException{
        if(closed){s.close();throw new IOException();}active=s;
    }
    synchronized void close(){
        closed=true;if(active!=null)try{active.close();}catch(IOException ignored){}active=null;
    }
    String summary(){return "BOOTSTRAP — Exit A="+status[0]+"; Exit B="+status[1]+"; Home="+status[2]+"; retries="+retries+"; plaintext fallback=0";}
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
        status[slot]=port==443?"authenticated-DoH":"authenticated-DoT";
        return a.ip;
    }
    String resolveTransferTarget()throws Exception{
        NativeEndpointDnsMessage.Answer answer=query("speed.cloudflare.com",1);
        if(answer==null)throw new Failure("TRANSFER_IPV4_MISSING");
        return answer.ip;
    }
    private synchronized boolean stopped(){return closed;}
    private NativeEndpointDnsMessage.Answer query(String host,int type)throws Exception{
        for(int attempt=0;;attempt++){
            try{return queryOnce(host,type);}
            catch(Failure failure){
                if(!NativeRoutingSafety.retryBootstrap(failure.code,attempt,deadline-SystemClock.elapsedRealtime(),stopped()||Thread.currentThread().isInterrupted()))throw failure;
                retries++;
                android.util.Log.i("WonheeAppRouting","BOOTSTRAP RETRY — same authenticated resolver; "+failure.code);
                Thread.sleep(200);
                if(stopped()||Thread.currentThread().isInterrupted())throw new Failure("STOPPED");
            }
        }
    }
    private NativeEndpointDnsMessage.Answer queryOnce(String host,int type)throws Exception{
        int id=port==443?0:new java.security.SecureRandom().nextInt(65536);
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
            raw.connect(new InetSocketAddress(InetAddress.getByAddress(resolverIp),port),timeout());
            raw.setSoTimeout(timeout());
            stage="tls-setup";
            SSLSocketFactory factory=(SSLSocketFactory)SSLSocketFactory.getDefault();
            try(SSLSocket tls=(SSLSocket)factory.createSocket(raw,tlsHost,port,true)){
                SSLParameters params=tls.getSSLParameters();
                params.setEndpointIdentificationAlgorithm("HTTPS");
                params.setServerNames(Collections.singletonList(new SNIHostName(tlsHost)));
                tls.setSSLParameters(params);
                stage="tls-handshake";
                tls.setSoTimeout(timeout());tls.startHandshake();
                stage=port==443?"doh-write":"dot-write";
                if(port==443)NativeBootstrapHttp.request(tls.getOutputStream(),q,tlsHost);
                else{DataOutputStream out=new DataOutputStream(tls.getOutputStream());out.writeShort(q.length);out.write(q);out.flush();}
                stage=port==443?"doh-read":"dot-read";
                InputStream bounded=new FilterInputStream(tls.getInputStream()){
                    @Override public int read()throws IOException{tls.setSoTimeout(timeout());return in.read();}
                    @Override public int read(byte[] b,int off,int len)throws IOException{tls.setSoTimeout(timeout());return in.read(b,off,len);}
                };
                byte[] b;
                if(port==443)b=NativeBootstrapHttp.response(new BufferedInputStream(bounded));
                else{DataInputStream in=new DataInputStream(bounded);int n=in.readUnsignedShort();if(n<12||n>16384)throw new IOException();b=new byte[n];in.readFully(b);}
                stage="dns-validate";
                return NativeEndpointDnsMessage.parse(b,host,id,type);
            }
        }catch(Failure failure){throw failure;}
        catch(Exception failure){throw new Failure(stage+"/"+category(failure));}
        finally{synchronized(this){active=null;}}
    }
}
