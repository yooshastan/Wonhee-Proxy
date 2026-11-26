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
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicIntegerArray;

/** Debug only. Exact host routes, own UID, one TCP connect per role; no payload or fallback. */
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
    private final Socket[] sockets=new Socket[3];
    private final AtomicIntegerArray localPorts=new AtomicIntegerArray(3), results=new AtomicIntegerArray(3);
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
    private void startProbes() throws Exception {
        stage="bind-probe-sockets";
        for(int i=0;i<count;i++){
            Socket socket=new Socket();sockets[i]=socket;
            vpn.bindSocket(socket);
            socket.bind(new InetSocketAddress(literal(TUN_IP),0));
            localPorts.set(i,socket.getLocalPort());
        }
        probesStarted=true;
        stage="tcp-probes";
        for(int i=0;i<count;i++){
            final int slot=i;final Socket socket=sockets[i];
            Thread worker=new Thread(()->{
                try{
                    socket.connect(new InetSocketAddress(literal(targets[slot]),ports[slot]),15000);
                    results.set(slot,1);
                }catch(Exception failure){results.set(slot,-1);}
                // Service owns socket close and TUN teardown.
            },"WonheeTcpProbe-"+i);
            worker.setDaemon(true);worker.start();
        }
    }
    private static int u16(byte[] p,int off){return ((p[off]&255)<<8)|(p[off+1]&255);}
    private static int ip(byte[] p,int off){return (u16(p,off)<<16)|u16(p,off+2);}
    private boolean match(byte[] p,int slot,boolean reply){
        if(p.length<40||p.length>1280||p[0]!=0x45||p[9]!=6||u16(p,2)!=p.length||(u16(p,6)&0xbfff)!=0)return false;
        int tcp=((p[32]&255)>>>4)*4;
        if(tcp<20||20+tcp!=p.length||localPorts.get(slot)==0)return false;
        int target=MultiTunnelIpv4Rewriter.parseIpv4(targets[slot]);
        int local=MultiTunnelIpv4Rewriter.parseIpv4(TUN_IP);
        // Inbound packet is translated before this check; original local address
        // is independently enforced by native scope and per-peer rewriter.
        return reply?ip(p,12)==target&&ip(p,16)==local&&u16(p,20)==ports[slot]&&u16(p,22)==localPorts.get(slot)
             :ip(p,12)==local&&ip(p,16)==target&&u16(p,20)==localPorts.get(slot)&&u16(p,22)==ports[slot];
    }
    private void pump() throws Exception {
        for(int k=0;k<16;k++){
            int n;
            try{n=Os.read(tun.getFileDescriptor(),buffer,0,buffer.length);}
            catch(ErrnoException e){if(e.errno==OsConstants.EAGAIN)break;throw e;}
            if(n<=0)throw new IllegalStateException();
            byte[] p=Arrays.copyOf(buffer,n);int slot=-1;
            for(int i=0;i<count;i++)if(match(p,i,false)){slot=i;break;}
            if(slot<0){rejected++;continue;}
            byte[] translated=rewrite[slot].toSession(p);
            if(translated==null||RootlessNativeBridge.injectPacket(handles[slot],translated)!=1)throw new IllegalStateException("egress rejected");
            outbound[slot]++;
        }
        for(int i=0;i<count;i++)for(int k=0;k<16;k++){
            int n=RootlessNativeBridge.pollProbePacket(handles[i],buffer);
            if(n==0)break;
            if(n<0){rejected++;if(n==-4)continue;throw new IllegalStateException();}
            byte[] p=rewrite[i].toTun(Arrays.copyOf(buffer,n));
            if(p==null||!match(p,i,true)){rejected++;continue;}
            if(Os.write(tun.getFileDescriptor(),p,0,p.length)!=p.length)throw new IllegalStateException("short TUN write");
            inbound[i]++;
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
                b.append(NativePeerProfiles.SLOTS[i]).append(": ").append(ok?"HANDSHAKE VERIFIED":"awaiting handshake").append(" · TCP=").append(results.get(i)==1?"CONNECTED":results.get(i)==-1?"FAILED":"pending").append(" · TUN out/in=").append(outbound[i]).append('/').append(inbound[i]).append('\n');
            }
            if(now>=deadline){finish("NOT PASSED — test timeout");return;}
            if(tun==null){
                if(!underlay.equals(physicalNetwork())){finish("NOT PASSED — network changed before TUN");return;}
                if(all)establish();
            }else{
                Network candidate=ownVpn();
                if(vpn==null){
                    if(candidate!=null){vpn=candidate;startProbes();}
                    else if(now-startedTun>5000L){finish("NOT PASSED — scoped VPN Network not visible");return;}
                }else if(!vpn.equals(candidate)){finish("NOT PASSED — scoped VPN Network lost");return;}
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
                complete &= results.get(i)==1 && outbound[i]>0 && inbound[i]>0 && stats[0]>0 && stats[1]>0;
                failed |= results.get(i)==-1;
            }
            last=(complete?"PASS":"RUNNING")+" — protected sockets="+p[0]+"; failures="+p[1]+"; policy rejections="+rejected+"\n"+b+"Own package and three host routes only; no application payload or DNS changes.";
            if(complete||failed||now>=reportAt){report(last);reportAt=now+1000L;}
            if(complete){finish("PASS — scoped bidirectional TCP verified");return;}
            if(failed){finish("NOT PASSED — TCP probe failed");return;}
            handler.postDelayed(tick,tun==null?250L:10L);
        }catch(Exception|LinkageError failure){finish("NOT PASSED — "+stage+" ("+failure.getClass().getSimpleName()+")");}
    }
    private Notification notification(){
        NotificationManager m=(NotificationManager)getSystemService(NOTIFICATION_SERVICE);
        if(m!=null)m.createNotificationChannel(new NotificationChannel(CHANNEL,"Native scoped TCP test",NotificationManager.IMPORTANCE_LOW));
        PendingIntent open=PendingIntent.getActivity(this,8401,new Intent(this,RootlessNativePeerActivity.class),PendingIntent.FLAG_IMMUTABLE|PendingIntent.FLAG_UPDATE_CURRENT);
        return new Notification.Builder(this,CHANNEL).setSmallIcon(R.drawable.ic_vpn_status).setContentTitle("Wonhee scoped TCP test").setContentText("Own package · no application payload").setContentIntent(open).setOngoing(true).build();
    }
    private void report(String s){Log.i(TAG,s);getSharedPreferences(PREFS,MODE_PRIVATE).edit().putString("status",s).apply();}
    private boolean cleanup(){
        handler.removeCallbacks(tick);boolean ok=true;
        // Close bound probe sockets first. They cannot fall back after TUN removal.
        for(int i=0;i<sockets.length;i++)if(sockets[i]!=null){try{sockets[i].close();}catch(Exception failure){ok=false;}sockets[i]=null;}
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
