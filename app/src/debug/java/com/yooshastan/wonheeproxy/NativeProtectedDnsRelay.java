package com.yooshastan.wonheeproxy;

import android.net.Network;
import android.os.SystemClock;
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
    final AtomicLong cacheHits=new AtomicLong(),tlsConnections=new AtomicLong(),tlsReuse=new AtomicLong(),tlsRetries=new AtomicLong(),tlsClosed=new AtomicLong();
    private static final long IDLE_LIMIT=30000;
    private static final int MAX_EXCHANGES=128;
    private final NativeDnsPositiveCache cache=new NativeDnsPositiveCache();
    private final ArrayDeque<Connection> idle=new ArrayDeque<>();
    private final ScheduledExecutorService reaper=Executors.newSingleThreadScheduledExecutor();
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
        reaper.scheduleWithFixedDelay(this::expireIdle,5,5,TimeUnit.SECONDS);
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
        byte[] cached=cache.get(query,SystemClock.elapsedRealtime());
        if(cached!=null){cacheHits.incrementAndGet();try{enqueue(packet,cached);}catch(IOException e){failed.incrementAndGet();}return;}
        try{workers.execute(()->{
            try{
                byte[] answer=exchange(query);verified.incrementAndGet();
                if(!closed)cache.put(query,answer,SystemClock.elapsedRealtime());
                enqueue(packet,answer);
            }
            catch(Exception e){failed.incrementAndGet();try{enqueue(packet,NativeProtectedDnsMessage.error(query,2,false));}catch(IOException ignored){}}
        });}catch(RejectedExecutionException full){overflow.incrementAndGet();try{enqueue(packet,NativeProtectedDnsMessage.error(query,2,false));}catch(IOException ignored){}}
    }
    private static InetAddress numeric(int n)throws UnknownHostException{return InetAddress.getByAddress(new byte[]{(byte)(n>>>24),(byte)(n>>>16),(byte)(n>>>8),(byte)n});}
    private final class Connection implements AutoCloseable {
        final Socket raw;final SSLSocket tls;final int port;
        final DataInputStream in;final DataOutputStream out;
        long lastUsed=SystemClock.elapsedRealtime();int exchanges;
        private boolean disposed;
        Connection(Socket raw,SSLSocket tls,int port)throws IOException{
            this.raw=raw;this.tls=tls;this.port=port;
            in=new DataInputStream(tls.getInputStream());out=new DataOutputStream(tls.getOutputStream());
        }
        byte[] query(byte[] q)throws IOException{
            out.writeShort(q.length);out.write(q);out.flush();
            int n=in.readUnsignedShort();if(n<12||n>16384)throw new IOException("DNS response size");
            byte[] answer=new byte[n];in.readFully(answer);
            byte[] checked=NativeProtectedDnsMessage.validate(q,answer);
            exchanges++;lastUsed=SystemClock.elapsedRealtime();return checked;
        }
        boolean expired(long now){return exchanges>=MAX_EXCHANGES||now-lastUsed>=IDLE_LIMIT||raw.isClosed()||tls.isClosed();}
        @Override public synchronized void close(){
            if(disposed)return;disposed=true;
            // Raw close is bounded and also wakes a worker blocked in TLS read.
            try{raw.close();}catch(IOException ignored){}
            try{tls.close();}catch(IOException ignored){}
            ports.remove(port,raw);sockets.remove(raw);tlsClosed.incrementAndGet();
        }
    }
    private Connection open()throws Exception{
        Socket raw=new Socket();SSLSocket tls=null;int port=0;boolean success=false;
        sockets.add(raw);
        try{
            if(closed)throw new IOException("relay stopped");
            network.bindSocket(raw);
            raw.bind(new InetSocketAddress(numeric(NativeAppRoutingPolicy.TUN),0));
            port=raw.getLocalPort();
            if(ports.putIfAbsent(port,raw)!=null)throw new IOException("port collision");
            if(closed)throw new IOException("relay stopped");
            raw.setSoTimeout(7000);
            raw.connect(new InetSocketAddress(numeric(ip),853),6000);
            tls=(SSLSocket)((SSLSocketFactory)SSLSocketFactory.getDefault()).createSocket(raw,HOSTS[provider],853,false);
            SSLParameters params=tls.getSSLParameters();params.setEndpointIdentificationAlgorithm("HTTPS");
            params.setServerNames(Collections.singletonList(new SNIHostName(HOSTS[provider])));tls.setSSLParameters(params);
            tls.setSoTimeout(7000);tls.startHandshake();
            if(closed)throw new IOException("relay stopped");
            Connection c=new Connection(raw,tls,port);success=true;tlsConnections.incrementAndGet();return c;
        }finally{
            if(!success){
                try{raw.close();}catch(IOException ignored){}
                if(tls!=null)try{tls.close();}catch(IOException ignored){}
                if(port!=0)ports.remove(port,raw);sockets.remove(raw);
            }
        }
    }
    private Connection takeIdle(){
        synchronized(idle){
            if(closed)return null;
            return idle.pollFirst();
        }
    }
    private void release(Connection c){
        boolean keep;
        synchronized(idle){
            keep=!closed&&!c.expired(SystemClock.elapsedRealtime())&&idle.size()<4;
            if(keep)idle.addLast(c);
        }
        if(!keep)c.close();
    }
    private void expireIdle(){
        List<Connection> expired=new ArrayList<>();
        synchronized(idle){
            long now=SystemClock.elapsedRealtime();
            Iterator<Connection> it=idle.iterator();
            while(it.hasNext()){Connection c=it.next();if(c.expired(now)){it.remove();expired.add(c);}}
        }
        for(Connection c:expired)c.close();
    }
    private byte[] exchange(byte[] query)throws Exception{
        if(closed)throw new IOException("relay stopped");
        Connection c=takeIdle();
        if(c!=null&&c.expired(SystemClock.elapsedRealtime())){c.close();c=null;}
        if(c!=null){
            try{
                tlsReuse.incrementAndGet();
                byte[] answer=c.query(query);release(c);return answer;
            }catch(IOException stale){
                c.close();
                if(closed)throw stale;
                // At most one fresh authenticated TLS connection, same provider and role.
                tlsRetries.incrementAndGet();
            }catch(RuntimeException failure){c.close();throw failure;}
        }
        c=open();
        try{byte[] answer=c.query(query);release(c);return answer;}
        catch(Exception failure){c.close();throw failure;}
    }
    int cacheSize(){return cache.size();}
    boolean awaitStopped(){
        boolean interrupted=Thread.interrupted();
        long deadline=SystemClock.elapsedRealtime()+4000;
        try{
            for(ExecutorService executor:new ExecutorService[]{workers,reaper}){
                while(!executor.isTerminated()){
                    long left=deadline-SystemClock.elapsedRealtime();if(left<=0)return false;
                    try{if(!executor.awaitTermination(left,TimeUnit.MILLISECONDS))return false;}
                    catch(InterruptedException e){interrupted=true;}
                }
            }
            return true;
        }finally{if(interrupted)Thread.currentThread().interrupt();}
    }
    @Override public void close(){
        closed=true;workers.shutdownNow();reaper.shutdownNow();
        List<Connection> drain;
        synchronized(idle){drain=new ArrayList<>(idle);idle.clear();}
        for(Socket s:sockets)try{s.close();}catch(IOException ignored){}
        for(Connection c:drain)c.close();
        cache.clear();replies.clear();
    }
}
