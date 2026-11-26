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
    static final String[] SECONDARY_IPS={"1.0.0.1","149.112.112.112","94.140.15.15","8.8.4.4"};
    static final String[] HOSTS={"cloudflare-dns.com","dns.quad9.net","dns.adguard-dns.com","dns.google"};
    final int role,ip,provider,mode,alternate;
    final String endpoint;
    final AtomicLong quicFreshRetries=new AtomicLong(),quicFreshFailures=new AtomicLong(),quicRetrySuccess=new AtomicLong(),quicHandshakeTimeout=new AtomicLong(),quicStreamReset=new AtomicLong(),quicRemoteClose=new AtomicLong(),quicTransportError=new AtomicLong(),quicTlsError=new AtomicLong(),probeAttempts=new AtomicLong(),probePassed=new AtomicLong(),probeFailed=new AtomicLong();
    private volatile String probeStatus="Not tested";
    private final java.util.concurrent.atomic.AtomicBoolean probeRunning=new java.util.concurrent.atomic.AtomicBoolean();
    private volatile long lastSuccessMs,lastFailureMs;
    private final NativeDnsFreshBackoff freshBackoff=new NativeDnsFreshBackoff();
    private final long tcpHandle;
    private final byte[] quicRoots;
    private final ArrayDeque<QuicConnection> quicIdle=new ArrayDeque<>();
    private final Set<QuicConnection> quicConnections=ConcurrentHashMap.newKeySet();
    final AtomicLong quicAttempts=new AtomicLong(),quicReused=new AtomicLong(),quicClosed=new AtomicLong(),quicBackoff=new AtomicLong(),quicTimeout=new AtomicLong(),quicCertificate=new AtomicLong(),quicSocketError=new AtomicLong(),quicOther=new AtomicLong(),quicInvalid=new AtomicLong(),coalesced=new AtomicLong();
    final AtomicLong dnsLatencySamples=new AtomicLong(),dnsLatencyTotalMs=new AtomicLong(),dnsLatencyMaxMs=new AtomicLong();
    private final Map<String,List<AnswerSink>> pending=new HashMap<>();
    final AtomicLong tcpQueries=new AtomicLong(),udpQueries=new AtomicLong(),tcpRejected=new AtomicLong(),udpTruncated=new AtomicLong(),quicOpened=new AtomicLong(),quicVerified=new AtomicLong(),quicFailed=new AtomicLong();
    private final Set<DatagramSocket> quicSockets=ConcurrentHashMap.newKeySet();
    private final ConcurrentHashMap<Integer,DatagramSocket> quicPorts=new ConcurrentHashMap<>();
    private final byte[] tcpScratch=new byte[1280];
    final AtomicLong queries=new AtomicLong(),blocked=new AtomicLong(),verified=new AtomicLong(),failed=new AtomicLong(),overflow=new AtomicLong();
    final AtomicLong cacheHits=new AtomicLong(),tlsConnections=new AtomicLong(),tlsReuse=new AtomicLong(),tlsRetries=new AtomicLong(),tlsClosed=new AtomicLong();
    final AtomicLong retryEof=new AtomicLong(),retryTimeout=new AtomicLong(),retryTls=new AtomicLong(),retryOther=new AtomicLong();
    int socketCount(){return sockets.size()+quicSockets.size();}
    int portCount(){return ports.size()+quicPorts.size();}
    private static final long IDLE_LIMIT=30000,QUIC_IDLE_LIMIT=10000;
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
    NativeProtectedDnsRelay(Network network,int provider,int role,int mode,int alternate,Set<String> domains)throws Exception{
        if(network==null||!NativeDnsTransportPolicy.supports(provider,mode)||role<0||role>1||alternate<0||alternate>1)throw new IllegalArgumentException();
        this.network=network;this.provider=provider;this.role=role;this.mode=mode;this.alternate=alternate;this.endpoint=(alternate==0?IPS:SECONDARY_IPS)[provider];this.ip=MultiTunnelIpv4Rewriter.parseIpv4(endpoint);this.domains=domains;
        long t=0;byte[] roots=null;
        try{
            if(mode!=NativeDnsTransportPolicy.DOT){
                roots=systemRoots();
            }
            t=NativeAdvancedDnsBridge.createTcp();
            if(t<=0)throw new IOException("TCP DNS initialization refused");
            reaper.scheduleWithFixedDelay(this::expireIdle,5,5,TimeUnit.SECONDS);
        }catch(Exception|LinkageError e){
            if(t>0)NativeAdvancedDnsBridge.closeTcp(t);
            workers.shutdownNow();reaper.shutdownNow();throw e;
        }
        quicRoots=roots;tcpHandle=t;
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
        // Exact normalized question and flags, excluding only the transaction ID.
        // Bound waiter count and total outstanding keys; never merge different questions.
        String key=Base64.getEncoder().encodeToString(Arrays.copyOfRange(query,2,query.length));
        AnswerSink waiter=answer->{
            byte[] copy=answer.clone();copy[0]=query[0];copy[1]=query[1];sink.send(copy);
        };
        synchronized(pending){
            if(closed)return;
            List<AnswerSink> list=pending.get(key);
            if(list!=null&&list.size()<16){list.add(waiter);coalesced.incrementAndGet();return;}
            if(list!=null||pending.size()>=68){overflow.incrementAndGet();try{sink.send(NativeProtectedDnsMessage.error(query,2,false));}catch(IOException ignored){}return;}
            List<AnswerSink> first=new ArrayList<>();first.add(waiter);pending.put(key,first);
        }
        try{workers.execute(()->{
            byte[] answer=null;boolean success=false;
            try{
                long started=SystemClock.elapsedRealtime();
                answer=mode==NativeDnsTransportPolicy.DOT?exchange(query):exchangeQuic(query);
                if(!closed){long elapsed=SystemClock.elapsedRealtime()-started;dnsLatencyTotalMs.addAndGet(elapsed);dnsLatencyMaxMs.accumulateAndGet(elapsed,Math::max);dnsLatencySamples.incrementAndGet();cache.put(query,answer,SystemClock.elapsedRealtime());success=true;}
            }catch(Exception|LinkageError e){
                if(!closed)try{answer=NativeProtectedDnsMessage.error(query,2,false);}catch(IOException ignored){}
            }finally{
                List<AnswerSink> list;
                synchronized(pending){list=pending.remove(key);}
                if(!closed&&list!=null){
                    if(success){verified.incrementAndGet();lastSuccessMs=SystemClock.elapsedRealtime();}else{failed.incrementAndGet();lastFailureMs=SystemClock.elapsedRealtime();}
                    if(answer!=null)for(AnswerSink target:list)try{target.send(answer);}catch(IOException e){overflow.incrementAndGet();}
                }
            }
        });}catch(RejectedExecutionException full){
            List<AnswerSink> list;synchronized(pending){list=pending.remove(key);}
            if(!closed&&list!=null){overflow.addAndGet(list.size());try{byte[] err=NativeProtectedDnsMessage.error(query,2,false);for(AnswerSink target:list)try{target.send(err);}catch(IOException ignored){}}catch(IOException ignored){}}
        }
    }
    String health(){
        if(closed)return "Stopped";
        if(freshBackoff.waiting(SystemClock.elapsedRealtime()))return "Degraded · fresh connection backoff";
        if(lastFailureMs>lastSuccessMs)return "Degraded · recent upstream failure";
        return lastSuccessMs>0?"Verified · authenticated upstream response":"Waiting for upstream verification";
    }
    String probeStatus(){return probeStatus;}
    // User-requested, fixed public test name, directly through the active relay.
    // Do not consult the cache or send application names; no provider/exit change.
    void testProvider(){
        if(closed||!probeRunning.compareAndSet(false,true))return;
        probeStatus="Testing…";
        byte[] q={0x12,0x34,1,0,0,1,0,0,0,0,0,0,7,101,120,97,109,112,108,101,3,99,111,109,0,0,1,0,1};
        try{workers.execute(()->{
            long start=SystemClock.elapsedRealtime();probeAttempts.incrementAndGet();
            try{
                byte[] answer=mode==NativeDnsTransportPolicy.DOT?exchange(q):exchangeQuic(q);
                if((answer[3]&15)!=0||((answer[6]&255)<<8|(answer[7]&255))==0)throw new IOException("test response has no answer");
                if(!closed){lastSuccessMs=SystemClock.elapsedRealtime();probePassed.incrementAndGet();probeStatus="Passed · "+(lastSuccessMs-start)+" ms";}
            }catch(Exception|LinkageError e){if(!closed){lastFailureMs=SystemClock.elapsedRealtime();probeFailed.incrementAndGet();probeStatus="Failed · see Activity counters";}}
            finally{probeRunning.set(false);}
        });}catch(RejectedExecutionException full){probeStatus="Busy · retry later";probeRunning.set(false);}
    }
    private final class QuicConnection implements AutoCloseable{
        final DatagramSocket raw;final int port;final long handle;
        long lastUsed=SystemClock.elapsedRealtime();int exchanges;
        private boolean disposed;
        QuicConnection(DatagramSocket raw,int port,long handle){this.raw=raw;this.port=port;this.handle=handle;}
        boolean expired(long now){return raw.isClosed()||exchanges>=MAX_EXCHANGES||now-lastUsed>=QUIC_IDLE_LIMIT;}
        byte[] query(byte[] query)throws Exception{
            try(ParcelFileDescriptor descriptor=ParcelFileDescriptor.fromDatagramSocket(raw)){
                byte[] output=new byte[NativeProtectedDnsMessage.MAX_REPLY];
                int n=NativeAdvancedDnsBridge.exchangeQuic(handle,descriptor.getFd(),query,output);
                if(n<12||n>output.length){
                    if(n==-3)quicTimeout.incrementAndGet();else if(n==-7){quicTimeout.incrementAndGet();quicHandshakeTimeout.incrementAndGet();}else if(n==-8)quicStreamReset.incrementAndGet();else if(n==-9)quicRemoteClose.incrementAndGet();else if(n==-10)quicTransportError.incrementAndGet();else if(n==-11)quicTlsError.incrementAndGet();else if(n==-4)quicCertificate.incrementAndGet();
                    else if(n==-1||n==-2)quicSocketError.incrementAndGet();else if(n==-6)quicInvalid.incrementAndGet();else quicOther.incrementAndGet();
                    throw new IOException("QUIC exchange refused");
                }
                byte[] answer;
                try{answer=NativeProtectedDnsMessage.validateFull(query,Arrays.copyOf(output,n));}
                catch(IOException invalid){quicInvalid.incrementAndGet();throw invalid;}
                exchanges++;lastUsed=SystemClock.elapsedRealtime();return answer;
            }
        }
        @Override public synchronized void close(){
            if(disposed)return;disposed=true;
            raw.close();
            try{NativeAdvancedDnsBridge.closeQuic(handle);}finally{
                quicPorts.remove(port,raw);quicSockets.remove(raw);quicConnections.remove(this);quicClosed.incrementAndGet();
            }
        }
    }
    private QuicConnection openQuic()throws Exception{
        DatagramSocket raw=new DatagramSocket(null);int port=0;long handle=0;boolean success=false;
        quicSockets.add(raw);
        try{
            if(closed)throw new IOException("relay stopped");
            network.bindSocket(raw);
            raw.bind(new InetSocketAddress(numeric(NativeAppRoutingPolicy.TUN),0));
            port=raw.getLocalPort();
            if(quicPorts.putIfAbsent(port,raw)!=null)throw new IOException("port collision");
            raw.connect(new InetSocketAddress(numeric(ip),NativeDnsTransportPolicy.port(mode)));
            handle=NativeAdvancedDnsBridge.createQuic(provider,mode,alternate,quicRoots);
            if(handle<=0)throw new IOException("QUIC initialization refused");
            QuicConnection c=new QuicConnection(raw,port,handle);
            quicConnections.add(c);
            if(closed){c.close();handle=0;throw new IOException("relay stopped");}
            quicOpened.incrementAndGet();success=true;return c;
        }finally{
            if(!success){raw.close();if(handle>0)NativeAdvancedDnsBridge.closeQuic(handle);if(port!=0)quicPorts.remove(port,raw);quicSockets.remove(raw);}
        }
    }
    private byte[] useQuic(QuicConnection c,byte[] query)throws Exception{
        byte[] answer=c.query(query);quicVerified.incrementAndGet();lastSuccessMs=SystemClock.elapsedRealtime();
        boolean keep;
        synchronized(quicIdle){keep=!closed&&!c.expired(SystemClock.elapsedRealtime())&&quicIdle.size()<4;if(keep)quicIdle.addLast(c);}
        if(!keep)c.close();
        return answer;
    }
    private byte[] exchangeQuic(byte[] query)throws Exception{
        if(closed)throw new IOException("relay stopped");
        QuicConnection c;
        synchronized(quicIdle){c=quicIdle.pollFirst();}
        if(c!=null&&c.expired(SystemClock.elapsedRealtime())){c.close();c=null;}
        boolean retry=false;
        if(c!=null){
            quicAttempts.incrementAndGet();quicReused.incrementAndGet();
            try{return useQuic(c,query);}
            catch(Exception|LinkageError stale){
                c.close();if(closed)throw stale;
                quicFailed.incrementAndGet();retry=true;
            }
        }
        // Only fresh connection failures open the circuit. Reuse remains possible
        // during backoff; after expiry a single fresh half-open trial is allowed.
        long ticket=freshBackoff.begin(SystemClock.elapsedRealtime());
        if(ticket<0){quicBackoff.incrementAndGet();throw new IOException("fresh QUIC backoff");}
        if(retry)quicFreshRetries.incrementAndGet();
        quicAttempts.incrementAndGet();
        c=null;boolean ok=false;
        try{
            if(closed)throw new IOException("relay stopped");
            try{c=openQuic();}catch(Exception|LinkageError e){quicSocketError.incrementAndGet();throw e;}
            byte[] answer=useQuic(c,query);
            ok=true;if(retry)quicRetrySuccess.incrementAndGet();return answer;
        }catch(Exception|LinkageError e){
            if(c!=null)c.close();
            if(!closed){quicFailed.incrementAndGet();quicFreshFailures.incrementAndGet();}
            throw e;
        }finally{freshBackoff.finish(ticket,ok,SystemClock.elapsedRealtime());}
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
        List<QuicConnection> stale=new ArrayList<>();
        synchronized(quicIdle){Iterator<QuicConnection> it=quicIdle.iterator();while(it.hasNext()){QuicConnection q=it.next();if(q.expired(SystemClock.elapsedRealtime())){it.remove();stale.add(q);}}}
        for(QuicConnection q:stale)q.close();
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
        NativeAdvancedDnsBridge.closeTcp(tcpHandle);
        for(DatagramSocket s:quicSockets)s.close();
        workers.shutdownNow();reaper.shutdownNow();
        synchronized(quicIdle){quicIdle.clear();}
        for(QuicConnection q:quicConnections)q.close();
        synchronized(pending){pending.clear();}
        List<Connection> drain;
        synchronized(idle){drain=new ArrayList<>(idle);idle.clear();}
        for(Socket s:sockets)try{s.close();}catch(IOException ignored){}
        for(Connection c:drain)c.close();
        cache.clear();replies.clear();
    }
}
