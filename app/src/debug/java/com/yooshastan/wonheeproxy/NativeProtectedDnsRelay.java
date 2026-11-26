package com.yooshastan.wonheeproxy;

import android.net.Network;
import android.os.SystemClock;
import android.os.ParcelFileDescriptor;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.nio.charset.StandardCharsets;
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
    final int role,ip,provider,mode;
    private final long quicHandle,tcpHandle;
    final AtomicLong tcpQueries=new AtomicLong(),udpQueries=new AtomicLong(),tcpRejected=new AtomicLong(),udpTruncated=new AtomicLong(),quicOpened=new AtomicLong(),quicVerified=new AtomicLong(),quicFailed=new AtomicLong();
    private final Set<DatagramSocket> quicSockets=ConcurrentHashMap.newKeySet();
    private final ConcurrentHashMap<Integer,DatagramSocket> quicPorts=new ConcurrentHashMap<>();
    private final byte[] tcpScratch=new byte[1280];
    final AtomicLong queries=new AtomicLong(),blocked=new AtomicLong(),verified=new AtomicLong(),failed=new AtomicLong(),overflow=new AtomicLong();
    final AtomicLong cacheHits=new AtomicLong(),tlsConnections=new AtomicLong(),tlsReuse=new AtomicLong(),tlsRetries=new AtomicLong(),tlsClosed=new AtomicLong();
    final AtomicLong retryEof=new AtomicLong(),retryTimeout=new AtomicLong(),retryTls=new AtomicLong(),retryOther=new AtomicLong();
    int socketCount(){return sockets.size()+quicSockets.size();}
    int portCount(){return ports.size()+quicPorts.size();}
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
    NativeProtectedDnsRelay(Network network,int provider,int role,int mode,Set<String> domains)throws Exception{
        if(network==null||!NativeDnsTransportPolicy.supports(provider,mode)||role<0||role>1)throw new IllegalArgumentException();
        this.network=network;this.provider=provider;this.role=role;this.mode=mode;this.ip=MultiTunnelIpv4Rewriter.parseIpv4(IPS[provider]);this.domains=domains;
        long q=0,t=0;
        try{
            if(mode!=NativeDnsTransportPolicy.DOT){
                q=NativeAdvancedDnsBridge.createQuic(provider,mode,systemRoots());
                if(q<=0)throw new IOException("QUIC initialization refused");
            }
            t=NativeAdvancedDnsBridge.createTcp();
            if(t<=0)throw new IOException("TCP DNS initialization refused");
            reaper.scheduleWithFixedDelay(this::expireIdle,5,5,TimeUnit.SECONDS);
        }catch(Exception|LinkageError e){
            if(q>0)NativeAdvancedDnsBridge.closeQuic(q);
            if(t>0)NativeAdvancedDnsBridge.closeTcp(t);
            workers.shutdownNow();reaper.shutdownNow();throw e;
        }
        quicHandle=q;tcpHandle=t;
    }
    // Android system trust roots only; Go verifies the hostname and certificate chain.
    private static byte[] systemRoots()throws Exception{
        KeyStore store=KeyStore.getInstance("AndroidCAStore");store.load(null);
        ByteArrayOutputStream pem=new ByteArrayOutputStream();
        Enumeration<String> aliases=store.aliases();
        while(aliases.hasMoreElements()){
            String alias=aliases.nextElement();if(!alias.startsWith("system:"))continue;
            java.security.cert.Certificate cert=store.getCertificate(alias);
            if(!(cert instanceof X509Certificate))continue;
            String encoded=Base64.getMimeEncoder(64,new byte[]{10}).encodeToString(cert.getEncoded());
            pem.write(("-----BEGIN CERTIFICATE-----\n"+encoded+"\n-----END CERTIFICATE-----\n").getBytes(StandardCharsets.US_ASCII));
            if(pem.size()>1048576)throw new IOException("CA store too large");
        }
        if(pem.size()==0)throw new IOException("system CA store unavailable");
        return pem.toByteArray();
    }
    boolean owns(NativeAppRoutingPolicy.Key k){
        if(k.remote!=ip||k.remotePort!=NativeDnsTransportPolicy.port(mode)||k.proto!=NativeDnsTransportPolicy.protocol(mode))return false;
        return mode==NativeDnsTransportPolicy.DOT?ports.containsKey(k.localPort):quicPorts.containsKey(k.localPort);
    }
    boolean feedTcp(byte[] packet){
        if(closed)return false;
        boolean ok=NativeAdvancedDnsBridge.feedTcp(tcpHandle,packet)==1;
        if(!ok)tcpRejected.incrementAndGet();return ok;
    }
    void drainTcpQueries(){
        if(closed)return;
        for(int i=0;i<16;i++){
            int n=NativeAdvancedDnsBridge.pollTcp(tcpHandle,1,tcpScratch);
            if(n<=0)break;if(n<25){tcpRejected.incrementAndGet();continue;}
            long token=0;for(int k=0;k<8;k++)token=(token<<8)|(tcpScratch[k]&255L);
            final long requestToken=token;
            tcpQueries.incrementAndGet();
            resolve(Arrays.copyOfRange(tcpScratch,8,n),answer->{
                if(!closed&&NativeAdvancedDnsBridge.answerTcp(tcpHandle,requestToken,answer)!=1)tcpRejected.incrementAndGet();
            });
        }
    }
    byte[] poll(){
        byte[] udp=replies.poll();if(udp!=null)return udp;
        if(closed)return null;
        int n=NativeAdvancedDnsBridge.pollTcp(tcpHandle,0,tcpScratch);
        return n>0?Arrays.copyOf(tcpScratch,n):null;
    }
    private interface AnswerSink{void send(byte[] response)throws IOException;}
    private void enqueue(byte[] request,byte[] response)throws IOException{
        if(response.length>NativeProtectedDnsMessage.udpLimit(Arrays.copyOfRange(request,28,request.length))){udpTruncated.incrementAndGet();response=NativeProtectedDnsMessage.error(response,0,true);}
        if(!closed&&!replies.offer(NativeProtectedDnsMessage.reply(request,response)))overflow.incrementAndGet();
    }
    void submit(byte[] packet){
        if(closed)return;udpQueries.incrementAndGet();
        resolve(Arrays.copyOfRange(packet,28,packet.length),answer->enqueue(packet,answer));
    }
    private void resolve(byte[] raw,AnswerSink sink){
        if(closed)return;queries.incrementAndGet();
        final byte[] query;
        try{query=NativeProtectedDnsMessage.normalize(raw);
            if(NativeProtectedDnsMessage.blocked(NativeProtectedDnsMessage.question(query).name,domains)){
                blocked.incrementAndGet();sink.send(NativeProtectedDnsMessage.error(query,3,false));return;
            }
        }catch(IOException malformed){failed.incrementAndGet();return;}
        byte[] cached=cache.get(query,SystemClock.elapsedRealtime());
        if(cached!=null){cacheHits.incrementAndGet();try{sink.send(cached);}catch(IOException e){failed.incrementAndGet();}return;}
        try{workers.execute(()->{
            try{
                byte[] answer=mode==NativeDnsTransportPolicy.DOT?exchange(query):exchangeQuic(query);
                verified.incrementAndGet();
                if(!closed)cache.put(query,answer,SystemClock.elapsedRealtime());
                if(!closed)sink.send(answer);
            }
            catch(Exception|LinkageError e){if(!closed){failed.incrementAndGet();try{sink.send(NativeProtectedDnsMessage.error(query,2,false));}catch(IOException ignored){}}}
        });}catch(RejectedExecutionException full){if(!closed){overflow.incrementAndGet();try{sink.send(NativeProtectedDnsMessage.error(query,2,false));}catch(IOException ignored){}}}
    }
    private byte[] exchangeQuic(byte[] query)throws Exception{
        DatagramSocket raw=new DatagramSocket(null);int port=0;boolean registered=false;
        quicSockets.add(raw);
        try{
            if(closed)throw new IOException("relay stopped");
            network.bindSocket(raw);
            raw.bind(new InetSocketAddress(numeric(NativeAppRoutingPolicy.TUN),0));
            port=raw.getLocalPort();
            if(quicPorts.putIfAbsent(port,raw)!=null)throw new IOException("port collision");
            registered=true;
            if(closed)throw new IOException("relay stopped");
            raw.connect(new InetSocketAddress(numeric(ip),NativeDnsTransportPolicy.port(mode)));
            // Native receives only a duplicate of this VPN-bound, connected descriptor.
            try(ParcelFileDescriptor descriptor=ParcelFileDescriptor.fromDatagramSocket(raw)){
                byte[] output=new byte[NativeProtectedDnsMessage.MAX_REPLY];
                quicOpened.incrementAndGet();
                int n=NativeAdvancedDnsBridge.exchangeQuic(quicHandle,descriptor.getFd(),query,output);
                if(n<12||n>output.length)throw new IOException("QUIC exchange failed");
                byte[] answer=NativeProtectedDnsMessage.validateFull(query,Arrays.copyOf(output,n));
                quicVerified.incrementAndGet();return answer;
            }
        }catch(Exception|LinkageError failure){quicFailed.incrementAndGet();throw failure;}
        finally{raw.close();if(registered)quicPorts.remove(port,raw);quicSockets.remove(raw);}
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
            byte[] checked=NativeProtectedDnsMessage.validateFull(q,answer);
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
                if(stale instanceof EOFException)retryEof.incrementAndGet();
                else if(stale instanceof SocketTimeoutException)retryTimeout.incrementAndGet();
                else if(stale instanceof SSLException)retryTls.incrementAndGet();
                else retryOther.incrementAndGet();
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
        closed=true;
        if(quicHandle>0)NativeAdvancedDnsBridge.closeQuic(quicHandle);
        NativeAdvancedDnsBridge.closeTcp(tcpHandle);
        for(DatagramSocket s:quicSockets)s.close();
        workers.shutdownNow();reaper.shutdownNow();
        List<Connection> drain;
        synchronized(idle){drain=new ArrayList<>(idle);idle.clear();}
        for(Socket s:sockets)try{s.close();}catch(IOException ignored){}
        for(Connection c:drain)c.close();
        cache.clear();replies.clear();
    }
}
