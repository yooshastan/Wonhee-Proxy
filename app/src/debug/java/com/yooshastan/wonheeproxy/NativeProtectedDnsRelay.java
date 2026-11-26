package com.yooshastan.wonheeproxy;

import android.net.Network;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import javax.net.ssl.*;

/** Dedicated bound sockets, no protect(), no system lookup or plaintext fallback. */
final class NativeProtectedDnsRelay implements AutoCloseable {
    static final String[] NAMES={"Cloudflare","Quad9","AdGuard","Google"};
    static final String[] IPS={"1.1.1.1","9.9.9.9","94.140.14.14","8.8.8.8"};
    static final String[] HOSTS={"cloudflare-dns.com","dns.quad9.net","dns.adguard-dns.com","dns.google"};
    final int role,ip,provider;
    final AtomicLong queries=new AtomicLong(),blocked=new AtomicLong(),verified=new AtomicLong(),failed=new AtomicLong(),overflow=new AtomicLong();
    private final Set<String> domains;
    private final Network network;
    private final Set<Socket> sockets=ConcurrentHashMap.newKeySet();
    private final ConcurrentHashMap<Integer,Socket> ports=new ConcurrentHashMap<>();
    private final ArrayBlockingQueue<byte[]> replies=new ArrayBlockingQueue<>(128);
    private final ThreadPoolExecutor workers=new ThreadPoolExecutor(4,4,0,TimeUnit.SECONDS,new ArrayBlockingQueue<>(64));
    private volatile boolean closed;
    NativeProtectedDnsRelay(Network network,int provider,int role,Set<String> domains){
        if(network==null||provider<0||provider>=IPS.length||role<0||role>1)throw new IllegalArgumentException();
        this.network=network;this.provider=provider;this.role=role;this.ip=MultiTunnelIpv4Rewriter.parseIpv4(IPS[provider]);this.domains=domains;
    }
    boolean owns(NativeAppRoutingPolicy.Key k){
        return k.proto==6&&k.remote==ip&&k.remotePort==853&&ports.containsKey(k.localPort);
    }
    byte[] poll(){return replies.poll();}
    private void enqueue(byte[] request,byte[] response)throws IOException{
        if(!closed&&!replies.offer(NativeProtectedDnsMessage.reply(request,response)))overflow.incrementAndGet();
    }
    void submit(byte[] packet){
        if(closed)return;queries.incrementAndGet();
        final byte[] query;
        try{query=NativeProtectedDnsMessage.normalize(Arrays.copyOfRange(packet,28,packet.length));
            if(NativeProtectedDnsMessage.blocked(NativeProtectedDnsMessage.question(query).name,domains)){
                blocked.incrementAndGet();enqueue(packet,NativeProtectedDnsMessage.error(query,3,false));return;
            }
        }catch(IOException malformed){failed.incrementAndGet();return;}
        try{workers.execute(()->{
            try{byte[] answer=exchange(query);verified.incrementAndGet();enqueue(packet,answer);}
            catch(Exception e){failed.incrementAndGet();try{enqueue(packet,NativeProtectedDnsMessage.error(query,2,false));}catch(IOException ignored){}}
        });}catch(RejectedExecutionException full){overflow.incrementAndGet();try{enqueue(packet,NativeProtectedDnsMessage.error(query,2,false));}catch(IOException ignored){}}
    }
    private static InetAddress numeric(int n)throws UnknownHostException{return InetAddress.getByAddress(new byte[]{(byte)(n>>>24),(byte)(n>>>16),(byte)(n>>>8),(byte)n});}
    private byte[] exchange(byte[] query)throws Exception{
        Socket raw=new Socket();int port=0;
        sockets.add(raw);
        try{
            if(closed)throw new IOException();
            network.bindSocket(raw);
            raw.bind(new InetSocketAddress(numeric(NativeAppRoutingPolicy.TUN),0));
            port=raw.getLocalPort();
            if(ports.putIfAbsent(port,raw)!=null)throw new IOException("port collision");
            if(closed)throw new IOException();
            raw.setSoTimeout(7000);
            raw.connect(new InetSocketAddress(numeric(ip),853),6000);
            try(SSLSocket tls=(SSLSocket)((SSLSocketFactory)SSLSocketFactory.getDefault()).createSocket(raw,HOSTS[provider],853,false)){
                SSLParameters params=tls.getSSLParameters();params.setEndpointIdentificationAlgorithm("HTTPS");
                params.setServerNames(Collections.singletonList(new SNIHostName(HOSTS[provider])));tls.setSSLParameters(params);
                tls.setSoTimeout(7000);tls.startHandshake();
                DataOutputStream out=new DataOutputStream(tls.getOutputStream());out.writeShort(query.length);out.write(query);out.flush();
                DataInputStream in=new DataInputStream(tls.getInputStream());int n=in.readUnsignedShort();
                if(n<12||n>16384)throw new IOException("DNS response size");
                byte[] response=new byte[n];in.readFully(response);
                return NativeProtectedDnsMessage.validate(query,response);
            }
        }finally{
            try{raw.close();}finally{if(port!=0)ports.remove(port,raw);sockets.remove(raw);}
        }
    }
    @Override public void close(){
        closed=true;workers.shutdownNow();for(Socket s:sockets)try{s.close();}catch(IOException ignored){}
        replies.clear();
    }
}
