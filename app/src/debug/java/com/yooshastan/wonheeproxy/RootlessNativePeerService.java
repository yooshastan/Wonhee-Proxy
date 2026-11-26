package com.yooshastan.wonheeproxy;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.LinkProperties;
import android.net.LinkAddress;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.os.SystemClock;
import android.provider.Settings;
import android.system.Os;
import android.system.OsConstants;
import android.system.ErrnoException;
import android.util.Log;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.security.SecureRandom;
import java.net.SocketException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLParameters;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicIntegerArray;

/** Debug only. Exact host routes, own UID, two owned TCP flows per role, bounded HTTP response, no credentials or fallback. */
public final class RootlessNativePeerService extends VpnService {
    static final String START="com.yooshastan.wonheeproxy.PEER_START";
    static final String STOP="com.yooshastan.wonheeproxy.PEER_STOP";
    static final String PREFS="wonhee_peer_handshake_v1";
    private static final String TAG="WonheeNativePeers", CHANNEL="wonhee_peer_handshake";
    private static final String TUN_IP="10.253.0.1";
    private final Handler handler=new Handler(Looper.getMainLooper());
    private final long[] handles=new long[3];
    private final String[] targets={"1.1.1.1","1.0.0.1",null};
    private final int[] ports={443,443,0}, outbound=new int[3], inbound=new int[3];
    private final MultiTunnelIpv4Rewriter[] rewrite=new MultiTunnelIpv4Rewriter[3];
    private static final int FLOWS=2;
    private final Socket[] sockets=new Socket[6];
    private final DatagramSocket[] udpSockets=new DatagramSocket[2];
    private final int[] udpPorts=new int[2], udpOut=new int[2], udpIn=new int[2];
    private final AtomicIntegerArray udpVerified=new AtomicIntegerArray(2), udpFailed=new AtomicIntegerArray(2);
    private final AtomicIntegerArray bodyBytes=new AtomicIntegerArray(6);
    private int rejectIpv6,rejectOther, rejectNative, rejectReply;
    private static final int UDP_COUNT=5;
    private static final byte[] QUESTION={7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};
    private final AtomicIntegerArray localPorts=new AtomicIntegerArray(6), results=new AtomicIntegerArray(6);
    private final AtomicIntegerArray httpStatus=new AtomicIntegerArray(6), responseBytes=new AtomicIntegerArray(6);
    private final int[] sentPayload=new int[6], receivedPayload=new int[6];
    private final java.util.concurrent.atomic.AtomicReferenceArray<String> workerStage=new java.util.concurrent.atomic.AtomicReferenceArray<>(6);
    private int bindAttempts;
    private long vpnSeenAt, nextBindAt, completedAt;
    private Network candidateSeen;
    private final byte[] buffer=new byte[1280];
    private ParcelFileDescriptor tun;
    private Network underlay,vpn;
    private int count,rejected;
    private long deadline,startedTun,reportAt;
    private boolean registered,started,terminal,probesStarted;
    private String last="No probe result.",stage="preflight";
    private final Runnable tick=this::pollPeers;

    static int validateHome(String host,String port) {
        int address=MultiTunnelIpv4Rewriter.parseIpv4(host);
        if(!((address>>>24)==10||(address&0xfff00000)==0xac100000||(address&0xffff0000)==0xc0a80000)
                || TUN_IP.equals(host))throw new IllegalArgumentException();
        int n=Integer.parseInt(port);if(n<1||n>65535)throw new IllegalArgumentException();
        return n;
    }
    @Override public int onStartCommand(Intent intent,int flags,int id){
        String action=intent==null?null:intent.getAction();
        if(STOP.equals(action)){finish("STOPPED");return START_NOT_STICKY;}
        if(!START.equals(action)){finish("STOPPED — no test requested");return START_NOT_STICKY;}
        if(started)return START_NOT_STICKY;started=true;
        try{
            Notification n=notification();
            if(Build.VERSION.SDK_INT>=34)startForeground(8401,n,ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
            else startForeground(8401,n);
            if(!RootlessNativeBridge.available()||VpnService.prepare(this)!=null||!dnsOff())throw new IllegalStateException();
            underlay=physicalNetwork();if(underlay==null)throw new IllegalStateException();
            stage="profile-validation";
            boolean home=intent.getBooleanExtra("home",true);
            if(home){targets[2]=intent.getStringExtra("target");ports[2]=validateHome(targets[2],intent.getStringExtra("port"));}
            String[] addresses=new String[3];
            String[] configs=NativePeerProfiles.prepare(this,home,intent.getStringArrayExtra("overrides"),addresses);
            count=configs.length;
            for(int i=0;i<count;i++)rewrite[i]=new MultiTunnelIpv4Rewriter(TUN_IP,addresses[i]);
            stage="callback-registration";
            if(!RootlessNativeBridge.setVpnService(this))throw new IllegalStateException();registered=true;
            for(int i=0;i<count;i++){
                stage="start-"+NativePeerProfiles.IDS[i];
                long h=RootlessNativeBridge.createProbeSession(NativePeerProfiles.IDS[i],configs[i],addresses[i],targets[i],ports[i]);
                if(h<=0){stage+="/native-code-"+h;throw new IllegalStateException();}
                handles[i]=h;configs[i]=null;
            }
            stage="socket-protection";
            long[] p=RootlessNativeBridge.protectionStats();
            if(p==null||p.length<2||p[0]!=2L*count||p[1]!=0)throw new IllegalStateException();
            deadline=SystemClock.elapsedRealtime()+120000L;
            stage="peer-handshakes";report("RUNNING — waiting for peer handshakes before creating scoped TUN.");
            handler.post(tick);
        }catch(NativePeerProfiles.Rejected failure){finish("NOT PASSED — "+stage+"/"+failure.code);}
        catch(Exception|LinkageError failure){finish("NOT PASSED — "+stage+" ("+failure.getClass().getSimpleName()+")");}
        return START_NOT_STICKY;
    }
    private boolean dnsOff(){return "off".equals(Settings.Global.getString(getContentResolver(),"private_dns_mode"));}
    private ConnectivityManager cm(){return (ConnectivityManager)getSystemService(Context.CONNECTIVITY_SERVICE);}
    private Network physicalNetwork(){
        ConnectivityManager m=cm();if(m==null)return null;
        for(Network n:m.getAllNetworks()){
            NetworkCapabilities c=m.getNetworkCapabilities(n);
            if(c!=null&&c.hasTransport(NetworkCapabilities.TRANSPORT_VPN))return null;
        }
        Network n=m.getActiveNetwork();return physical(n)?n:null;
    }
    private boolean physical(Network n){
        NetworkCapabilities c=n==null?null:cm().getNetworkCapabilities(n);
        return c!=null&&!c.hasTransport(NetworkCapabilities.TRANSPORT_VPN)&&(c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)||c.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR));
    }
    private Network ownVpn() {
        Network found=null;
        for(Network n:cm().getAllNetworks()){
            NetworkCapabilities c=cm().getNetworkCapabilities(n);
            if(c==null||!c.hasTransport(NetworkCapabilities.TRANSPORT_VPN))continue;
            LinkProperties lp=cm().getLinkProperties(n);boolean address=false;
            if(lp!=null)for(LinkAddress a:lp.getLinkAddresses())if(a.getPrefixLength()==32&&TUN_IP.equals(a.getAddress().getHostAddress()))address=true;
            if(!address||found!=null)return null;
            found=n;
        }
        return found;
    }
    private void establish() throws Exception {
        stage="establish-scoped-tun";
        Builder builder=new Builder().setSession("Wonhee scoped TCP probe").setMtu(1280).setBlocking(false).addAddress(TUN_IP,32);
        builder.addAllowedApplication(getPackageName());
        builder.setUnderlyingNetworks(new Network[]{underlay});
        for(int i=0;i<count;i++)builder.addRoute(targets[i],32);
        tun=builder.establish();if(tun==null)throw new IllegalStateException();
        startedTun=SystemClock.elapsedRealtime();
    }
    private static InetAddress literal(String ip)throws Exception{
        int a=MultiTunnelIpv4Rewriter.parseIpv4(ip);
        return InetAddress.getByAddress(new byte[]{(byte)(a>>>24),(byte)(a>>>16),(byte)(a>>>8),(byte)a});
    }
    // Retry only before registration and before ANY connect. No unbound retry.
    private boolean startProbes() throws Exception {
        bindAttempts++;
        try {
            for(int f=0;f<count*FLOWS;f++){
                stage="bind-vpn-"+NativePeerProfiles.IDS[f/FLOWS]+"-flow-"+(f%FLOWS+1);
                Socket socket=new Socket();sockets[f]=socket;
                vpn.bindSocket(socket);
                stage="bind-tun-source-"+NativePeerProfiles.IDS[f/FLOWS]+"-flow-"+(f%FLOWS+1);
                socket.bind(new InetSocketAddress(literal(TUN_IP),0));
                localPorts.set(f,socket.getLocalPort());
            }
            for(int i=0;i<2;i++){
                stage="bind-udp-"+NativePeerProfiles.IDS[i];
                DatagramSocket udp=new DatagramSocket(null);udpSockets[i]=udp;
                vpn.bindSocket(udp);
                udp.bind(new InetSocketAddress(literal(TUN_IP),0));udpPorts[i]=udp.getLocalPort();
            }
        }catch(SocketException failure){
            String failedStage=stage;
            for(int f=0;f<sockets.length;f++){
                if(sockets[f]!=null){try{sockets[f].close();}catch(Exception closeFailed){throw new IllegalStateException("pre-connect cleanup failed");}sockets[f]=null;}
                localPorts.set(f,0);
            }
            for(int i=0;i<2;i++){if(udpSockets[i]!=null){udpSockets[i].close();udpSockets[i]=null;}udpPorts[i]=0;}
            if(bindAttempts>=4)throw failure;
            nextBindAt=SystemClock.elapsedRealtime()+400L;
            report("RUNNING — "+failedStage+" retry "+bindAttempts+"/4; no connects started.");
            return false;
        }
        for(int i=0;i<count;i++){
            stage="register-flow-ports-"+NativePeerProfiles.IDS[i];
            if(!RootlessNativeBridge.registerProbePorts(handles[i],localPorts.get(i*FLOWS),localPorts.get(i*FLOWS+1),i<2?udpPorts[i]:0))throw new IllegalStateException();
        }
        probesStarted=true;
        stage="http-probes";
        for(int f=0;f<count*FLOWS;f++){
            final int flow=f,slot=f/FLOWS;final Socket socket=sockets[f];
            Thread worker=new Thread(()->runHttpProbe(flow,slot,socket),"WonheeHttpProbe-"+f);
            worker.setDaemon(true);worker.start();
        }
        for(int i=0;i<2;i++){
            final int slot=i;final DatagramSocket udp=udpSockets[i];
            Thread worker=new Thread(()->runUdpProbe(slot,udp),"WonheeUdpProbe-"+i);
            worker.setDaemon(true);worker.start();
        }
        return true;
    }
    private void runUdpProbe(int slot,DatagramSocket udp){
        try{
            udp.connect(new InetSocketAddress(literal(targets[slot]),53));
            udp.setSoTimeout(4000);
            int base=new SecureRandom().nextInt(65536);
            for(int k=0;k<UDP_COUNT;k++){
                int id=(base+k)&65535;
                byte[] query=new byte[12+QUESTION.length];
                query[0]=(byte)(id>>>8);query[1]=(byte)id;query[2]=1;query[5]=1;
                System.arraycopy(QUESTION,0,query,12,QUESTION.length);
                udp.send(new DatagramPacket(query,query.length));
                byte[] response=new byte[1252];DatagramPacket packet=new DatagramPacket(response,response.length);
                udp.receive(packet);
                int n=packet.getLength();
                if(n<query.length||u16(response,0)!=id||(response[2]&0xfa)!=0x80
                        ||(response[3]&15)!=0||u16(response,4)!=1||u16(response,6)==0
                        ||!literal(targets[slot]).equals(packet.getAddress())||packet.getPort()!=53)
                    throw new java.io.IOException("DNS transaction mismatch");
                for(int j=0;j<QUESTION.length;j++)if(response[12+j]!=QUESTION[j])throw new java.io.IOException("DNS question mismatch");
                udpVerified.incrementAndGet(slot);
                if(k+1<UDP_COUNT)Thread.sleep(1000L);
            }
        }catch(Exception failure){udpFailed.set(slot,1);Log.i(TAG,"UDP "+NativePeerProfiles.IDS[slot]+" failed ("+failure.getClass().getSimpleName()+")");}
    }
    private void runHttpProbe(int flow,int slot,Socket socket){
        SSLSocket tls=null;
        try{
            workerStage.set(flow,"connect");
            socket.setSoTimeout(12000);
            socket.connect(new InetSocketAddress(literal(targets[slot]),ports[slot]),15000);
            Socket wire=socket;
            String host=targets[slot];
            if(slot<2){
                workerStage.set(flow,"verified-tls");
                host="cloudflare-dns.com";
                tls=(SSLSocket)((SSLSocketFactory)SSLSocketFactory.getDefault()).createSocket(socket,host,ports[slot],false);
                SSLParameters parameters=tls.getSSLParameters();
                parameters.setEndpointIdentificationAlgorithm("HTTPS");
                tls.setSSLParameters(parameters);tls.setSoTimeout(12000);tls.startHandshake();
                wire=tls;
            }
            workerStage.set(flow,"http-response");
            // No auth, cookies, redirects, user input or DNS lookup. Only fixed GET.
            String crlf=String.valueOf((char)13)+(char)10;
            String request="GET / HTTP/1.1"+crlf+"Host: "+host+(slot==2?":"+ports[slot]:"")+crlf
                    +"Connection: close"+crlf+"User-Agent: Wonhee-Diagnostic/0.15.89"+crlf+"Accept: */*"+crlf+crlf;
            wire.getOutputStream().write(request.getBytes(StandardCharsets.US_ASCII));
            wire.getOutputStream().flush();
            InputStream in=wire.getInputStream();
            byte[] head=new byte[8192];int n=0;
            long until=SystemClock.elapsedRealtime()+12000L;
            while(n<head.length&&SystemClock.elapsedRealtime()<until){
                int value=in.read();if(value<0)break;
                head[n++]=(byte)value;
                if(n>=4&&head[n-4]==13&&head[n-3]==10&&head[n-2]==13&&head[n-1]==10)break;
            }
            if(n<12||head[n-4]!=13||head[n-3]!=10||head[n-2]!=13||head[n-1]!=10)throw new java.io.IOException("header incomplete");
            String line=new String(head,0,Math.min(n,64),StandardCharsets.US_ASCII);
            if(!(line.startsWith("HTTP/1.0 ")||line.startsWith("HTTP/1.1 "))||line.length()<13
                    ||line.charAt(9)<'1'||line.charAt(9)>'5'||line.charAt(10)<'0'||line.charAt(10)>'9'
                    ||line.charAt(11)<'0'||line.charAt(11)>'9'||(line.charAt(12)!=' '&&line.charAt(12)!=13))
                throw new java.io.IOException("invalid status");
            httpStatus.set(flow,Integer.parseInt(line.substring(9,12)));
            responseBytes.set(flow,n);
            String headers=new String(head,0,n,StandardCharsets.US_ASCII);
            int advertised=0;boolean lengthSeen=false;
            for(String header:headers.split(String.valueOf((char)13)+(char)10)){
                if(header.regionMatches(true,0,"Content-Length:",0,15)){
                    if(lengthSeen)throw new java.io.IOException("duplicate content length");
                    lengthSeen=true;
                    String value=header.substring(15).trim();
                    if(!value.matches("[0-9]{1,18}"))throw new java.io.IOException("invalid content length");
                    advertised=(int)Math.min(65536L,Long.parseLong(value));
                }
            }
            if(headers.toLowerCase(java.util.Locale.ROOT).contains("transfer-encoding:"))advertised=0;
            byte[] body=new byte[4096];int read=0;
            while(read<advertised){
                if(SystemClock.elapsedRealtime()>=until)throw new java.io.IOException("body deadline");
                int got=in.read(body,0,Math.min(body.length,advertised-read));if(got<=0)throw new java.io.IOException("short body");
                read+=got;
            }
            bodyBytes.set(flow,read);
            workerStage.set(flow,"response-verified");
            results.set(flow,1);
        }catch(Exception failure){
            workerStage.set(flow,workerStage.get(flow)+"/"+failure.getClass().getSimpleName());
            results.set(flow,-1);
        }finally{
            // Underlying bound socket is always owned by service; TLS wrapper never reconnects.
            if(tls!=null)try{tls.close();}catch(Exception ignored){}
        }
    }
    private static int u16(byte[] p,int off){return ((p[off]&255)<<8)|(p[off+1]&255);}
    private static int ip(byte[] p,int off){return (u16(p,off)<<16)|u16(p,off+2);}
    private boolean match(byte[] p,int flow,boolean reply){
        int slot=flow/FLOWS;
        if(p.length<40||p.length>1280||p[0]!=0x45||p[9]!=6||u16(p,2)!=p.length||(u16(p,6)&0xbfff)!=0)return false;
        int tcp=((p[32]&255)>>>4)*4;
        if(tcp<20||20+tcp>p.length||localPorts.get(flow)==0)return false;
        int target=MultiTunnelIpv4Rewriter.parseIpv4(targets[slot]);
        int local=MultiTunnelIpv4Rewriter.parseIpv4(TUN_IP);
        // Inbound packet is translated before this check; original local address
        // is independently enforced by native scope and per-peer rewriter.
        return reply?ip(p,12)==target&&ip(p,16)==local&&u16(p,20)==ports[slot]&&u16(p,22)==localPorts.get(flow)
             :ip(p,12)==local&&ip(p,16)==target&&u16(p,20)==localPorts.get(flow)&&u16(p,22)==ports[slot];
    }
    private boolean matchUdp(byte[] p,int slot,boolean reply){
        if(slot<0||slot>=2||udpPorts[slot]==0||p.length<28||p.length>1280||p[0]!=0x45||p[9]!=17
                ||u16(p,2)!=p.length||(u16(p,6)&0xbfff)!=0||u16(p,24)!=p.length-20)return false;
        int target=MultiTunnelIpv4Rewriter.parseIpv4(targets[slot]),local=MultiTunnelIpv4Rewriter.parseIpv4(TUN_IP);
        return reply?ip(p,12)==target&&ip(p,16)==local&&u16(p,20)==53&&u16(p,22)==udpPorts[slot]
             :ip(p,12)==local&&ip(p,16)==target&&u16(p,20)==udpPorts[slot]&&u16(p,22)==53;
    }
    private void pump() throws Exception {
        for(int k=0;k<16;k++){
            int n;
            try{n=Os.read(tun.getFileDescriptor(),buffer,0,buffer.length);}
            catch(ErrnoException e){if(e.errno==OsConstants.EAGAIN)break;throw e;}
            if(n<=0)throw new IllegalStateException();
            byte[] p=Arrays.copyOf(buffer,n);int flow=-1;
            for(int i=0;i<count*FLOWS;i++)if(match(p,i,false)){flow=i;break;}
            if(flow<0){
                int udpSlot=-1;for(int i=0;i<2;i++)if(matchUdp(p,i,false)){udpSlot=i;break;}
                if(udpSlot>=0){
                    byte[] translated=rewrite[udpSlot].toSession(p);
                    if(translated==null||RootlessNativeBridge.injectPacket(handles[udpSlot],translated)!=1)throw new IllegalStateException("UDP egress rejected");
                    udpOut[udpSlot]++;continue;
                }
                rejected++;if((p[0]&0xf0)==0x60)rejectIpv6++;else rejectOther++;continue;
            }
            int slot=flow/FLOWS;
            byte[] translated=rewrite[slot].toSession(p);
            if(translated==null||RootlessNativeBridge.injectPacket(handles[slot],translated)!=1)throw new IllegalStateException("egress rejected");
            outbound[slot]++;
            sentPayload[flow]+=p.length-20-((p[32]&255)>>>4)*4;
        }
        for(int i=0;i<count;i++)for(int k=0;k<16;k++){
            int n=RootlessNativeBridge.pollProbePacket(handles[i],buffer);
            if(n==0)break;
            if(n<0){rejected++;rejectNative++;if(n==-4)continue;throw new IllegalStateException();}
            byte[] p=rewrite[i].toTun(Arrays.copyOf(buffer,n));
            int flow=-1;
            if(p!=null)for(int f=i*FLOWS;f<(i+1)*FLOWS;f++)if(match(p,f,true)){flow=f;break;}
            if(flow<0){
                if(p!=null&&matchUdp(p,i,true)){
                    if(Os.write(tun.getFileDescriptor(),p,0,p.length)!=p.length)throw new IllegalStateException("short UDP TUN write");
                    udpIn[i]++;continue;
                }
                rejected++;rejectReply++;continue;
            }
            if(Os.write(tun.getFileDescriptor(),p,0,p.length)!=p.length)throw new IllegalStateException("short TUN write");
            inbound[i]++;
            receivedPayload[flow]+=p.length-20-((p[32]&255)>>>4)*4;
        }
    }
    private void pollPeers(){
        if(terminal)return;
        try{
            long now=SystemClock.elapsedRealtime();
            if(!dnsOff()||!physical(underlay)){finish("NOT PASSED — underlay or DNS setting changed");return;}
            long[] p=RootlessNativeBridge.protectionStats();
            if(p==null||p.length<2||p[0]!=2L*count||p[1]!=0){finish("NOT PASSED — protection counters changed");return;}
            boolean all=true;StringBuilder b=new StringBuilder();
            for(int i=0;i<count;i++){
                long[] s=RootlessNativeBridge.peerStats(handles[i]);
                if(s==null||s.length<3||s[0]<0||s[1]<0||s[2]<0){finish("NOT PASSED — peer statistics unavailable");return;}
                boolean ok=s[0]>0&&s[1]>0&&s[2]>0;all &=ok;
                b.append(NativePeerProfiles.SLOTS[i]).append(": ").append(ok?"HANDSHAKE VERIFIED":"awaiting handshake").append(" · TUN out/in=").append(outbound[i]).append('/').append(inbound[i]).append('\n');
                for(int f=i*FLOWS;f<(i+1)*FLOWS;f++){
                    b.append("  flow ").append(f%FLOWS+1).append(": ").append(workerStage.get(f)==null?"pending":workerStage.get(f))
                     .append(" HTTP=").append(httpStatus.get(f)).append(" header bytes=").append(responseBytes.get(f)).append(" body sample=").append(bodyBytes.get(f))
                     .append(" TCP payload out/in=").append(sentPayload[f]).append('/').append(receivedPayload[f]).append('\n');
                }
                if(i<2)b.append("  UDP DNS transactions=").append(udpVerified.get(i)).append('/').append(UDP_COUNT)
                     .append(" TUN UDP out/in=").append(udpOut[i]).append('/').append(udpIn[i]).append(" failed=").append(udpFailed.get(i)).append('\n');
            }
            if(now>=deadline){finish("NOT PASSED — test timeout");return;}
            if(tun==null){
                if(!underlay.equals(physicalNetwork())){finish("NOT PASSED — network changed before TUN");return;}
                if(all)establish();
            }else{
                Network candidate=ownVpn();
                if(vpn==null){
                    if(candidate==null){candidateSeen=null;if(now-startedTun>8000L){finish("NOT PASSED — scoped VPN Network not visible");return;}}
                    else if(!candidate.equals(candidateSeen)){candidateSeen=candidate;vpnSeenAt=now;}
                    else if(now-vpnSeenAt>=500L){vpn=candidate;nextBindAt=now;}
                }else if(!vpn.equals(candidate)){finish("NOT PASSED — scoped VPN Network lost");return;}
                if(vpn!=null&&!probesStarted&&now>=nextBindAt)startProbes();
                if(vpn!=null){
                    Network active=cm().getActiveNetwork();
                    if(!vpn.equals(active)&&!underlay.equals(active)){finish("NOT PASSED — network changed");return;}
                    pump();
                }
            }
            boolean complete=probesStarted,failed=false;
            for(int i=0;i<count;i++){
                long[] stats=RootlessNativeBridge.packetStats(handles[i]);
                if(stats==null||stats.length<3||stats[2]!=0){finish("NOT PASSED — native queue error");return;}
                complete &= outbound[i]>0 && inbound[i]>0 && stats[0]>0 && stats[1]>0;
                if(i<2){complete &= udpVerified.get(i)==UDP_COUNT&&udpOut[i]>=UDP_COUNT&&udpIn[i]>=UDP_COUNT;failed |= udpFailed.get(i)!=0;}
                for(int f=i*FLOWS;f<(i+1)*FLOWS;f++){
                    complete &= results.get(f)==1 && httpStatus.get(f)>=100 && responseBytes.get(f)>0 && sentPayload[f]>0 && receivedPayload[f]>0;
                    failed |= results.get(f)==-1;
                }
            }
            if(complete&&completedAt==0)completedAt=now;
            boolean settled=complete&&now-completedAt>=3000L;
            last=(settled?"PASS":"RUNNING")+" — protected sockets="+p[0]+"; failures="+p[1]+"; policy rejections="+rejected+" (IPv6="+rejectIpv6+", other="+rejectOther+", native="+rejectNative+", reply="+rejectReply+"); bind attempts="+bindAttempts+"\n"+b+"Two HTTP flows per peer plus five fixed UDP DNS probes per exit; no credentials, redirects or system DNS changes.";
            if(settled||failed||now>=reportAt){report(last);reportAt=now+1000L;}
            if(settled){finish("PASS — concurrent scoped HTTP and UDP transactions verified");return;}
            if(failed){finish("NOT PASSED — TCP or UDP probe failed");return;}
            handler.postDelayed(tick,tun==null?250L:10L);
        }catch(Exception|LinkageError failure){finish("NOT PASSED — "+stage+" ("+failure.getClass().getSimpleName()+")");}
    }
    private Notification notification(){
        NotificationManager m=(NotificationManager)getSystemService(NOTIFICATION_SERVICE);
        if(m!=null)m.createNotificationChannel(new NotificationChannel(CHANNEL,"Native scoped HTTP test",NotificationManager.IMPORTANCE_LOW));
        PendingIntent open=PendingIntent.getActivity(this,8401,new Intent(this,RootlessNativePeerActivity.class),PendingIntent.FLAG_IMMUTABLE|PendingIntent.FLAG_UPDATE_CURRENT);
        return new Notification.Builder(this,CHANNEL).setSmallIcon(R.drawable.ic_vpn_status).setContentTitle("Wonhee scoped HTTP test").setContentText("Own package · credential-free HTTP probes").setContentIntent(open).setOngoing(true).build();
    }
    private void report(String s){Log.i(TAG,s);getSharedPreferences(PREFS,MODE_PRIVATE).edit().putString("status",s).apply();}
    private boolean cleanup(){
        handler.removeCallbacks(tick);boolean ok=true;
        // Close bound probe sockets first. They cannot fall back after TUN removal.
        for(int i=0;i<sockets.length;i++)if(sockets[i]!=null){try{sockets[i].close();}catch(Exception failure){ok=false;}sockets[i]=null;}
        for(int i=0;i<2;i++)if(udpSockets[i]!=null){udpSockets[i].close();udpSockets[i]=null;}
        if(tun!=null){try{tun.close();}catch(Exception failure){ok=false;}tun=null;}
        for(int i=handles.length-1;i>=0;i--)if(handles[i]>0){
            try{if(!RootlessNativeBridge.closeSession(handles[i]))ok=false;}catch(RuntimeException|LinkageError failure){ok=false;}
            handles[i]=0;
        }
        if(registered){try{if(!RootlessNativeBridge.clearVpnService(this))ok=false;}catch(RuntimeException|LinkageError failure){ok=false;}registered=false;}
        stopForeground(STOP_FOREGROUND_REMOVE);return ok;
    }
    private void finish(String reason){if(terminal)return;terminal=true;boolean ok=cleanup();report(reason+" — "+(ok?"native peer sessions released; TUN closed":"cleanup unconfirmed; force stop diagnostic")+"\nLast report:\n"+last);stopSelf();}
    @Override public void onRevoke(){finish("STOPPED — VPN permission revoked");}
    @Override public void onDestroy(){if(!terminal){terminal=true;boolean ok=cleanup();report("STOPPED unexpectedly — "+(ok?"sessions released":"cleanup unconfirmed")+"\n"+last);}super.onDestroy();}
}
