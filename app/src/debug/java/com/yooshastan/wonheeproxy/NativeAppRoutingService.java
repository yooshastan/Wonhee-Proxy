package com.yooshastan.wonheeproxy;

import android.app.*;
import android.content.*;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.net.*;
import android.os.*;
import android.provider.Settings;
import android.system.*;
import android.util.Log;
import java.net.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

/** Opt-in debug app routing. No root, no live policy mutation, no direct fallback. */
public final class NativeAppRoutingService extends VpnService {
    static final String START="com.yooshastan.wonheeproxy.APP_ROUTE_START",STOP="com.yooshastan.wonheeproxy.APP_ROUTE_STOP";
    static final String PREFS="native_app_route_status",TAG="WonheeAppRouting";
    static final int UNKNOWN_DNS=-2, RELAY_UID=-3;
    static final String GUARD_TEST="com.yooshastan.wonheeproxy.APP_ROUTE_GUARD_TEST";
    private volatile boolean guardTest;
    private static volatile boolean serviceRunning;
    static boolean running(){return serviceRunning;}
    private long lastSample,lastOut,lastIn,upRate,downRate;
    private long deniedRoute,deniedLedger,deniedNative,relayEnded;
    private String notificationLine="Connecting…";
    private NativeProtectedDnsRelay dnsRelay;
    private long dnsFirewallDrops,ipv6Drops,otherUnsupported;
    private boolean blockExternal853;
    private int dnsProvider,dnsRole;
    private Set<String> blocklist=Collections.emptySet();
    private final AtomicBoolean started=new AtomicBoolean();
    private volatile boolean stopping;
    private volatile NativeEndpointBootstrap bootstrap;
    private Thread worker;
    private final long[] handles=new long[3];
    private final MultiTunnelIpv4Rewriter[] rewrite=new MultiTunnelIpv4Rewriter[3];
    private final NativeAppRoutingPolicy.Ledger ledger=new NativeAppRoutingPolicy.Ledger();
    private final Map<Integer,NativeAppRoutingPolicy.App> owners=new HashMap<>();
    private final long[] outgoing=new long[3],incoming=new long[3],outBytes=new long[3],inBytes=new long[3],opened=new long[3];
    private long unknown,policyDrop,unsupported,foreignReply,queueDrop;
    private boolean registered,cleanupFailed;
    private ParcelFileDescriptor tun;
    private Network underlay;
    private NativeAppRoutingPolicy policy;
    private int count;
    private final byte[] buffer=new byte[1280];
    @Override public int onStartCommand(Intent intent,int flags,int id){
        String action=intent==null?null:intent.getAction();
        if(GUARD_TEST.equals(action)){if(started.get())guardTest=true;else stopSelf();return START_NOT_STICKY;}
        if(STOP.equals(action)){requestStop();if(!started.get())stopSelf();return START_NOT_STICKY;}
        if(!START.equals(action)){if(!started.get())stopSelf();return START_NOT_STICKY;}
        if(!started.compareAndSet(false,true))return START_NOT_STICKY;
        serviceRunning=true;
        Notification n=notification();
        if(Build.VERSION.SDK_INT>=34)startForeground(8402,n,ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);else startForeground(8402,n);
        report("STARTING — selected apps are not captured until VPN establishment");
        worker=new Thread(()->run(intent),"WonheeAppRoutingWorker");worker.start();
        return START_NOT_STICKY;
    }
    private void requestStop(){stopping=true;NativeEndpointBootstrap b=bootstrap;if(b!=null)b.close();if(worker!=null)worker.interrupt();}
    @Override public void onRevoke(){requestStop();super.onRevoke();}
    @Override public void onDestroy(){requestStop();super.onDestroy();}
    private ConnectivityManager cm(){return (ConnectivityManager)getSystemService(CONNECTIVITY_SERVICE);}
    private boolean dnsOff(){return "off".equals(Settings.Global.getString(getContentResolver(),"private_dns_mode"));}
    private boolean physical(Network n){
        NetworkCapabilities c=n==null?null:cm().getNetworkCapabilities(n);
        return c!=null&&!c.hasTransport(NetworkCapabilities.TRANSPORT_VPN)&&(c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)||c.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR));
    }
    private Network initialNetwork(){
        for(Network n:cm().getAllNetworks()){NetworkCapabilities c=cm().getNetworkCapabilities(n);if(c!=null&&c.hasTransport(NetworkCapabilities.TRANSPORT_VPN))return null;}
        Network n=cm().getActiveNetwork();return physical(n)?n:null;
    }
    private boolean ownNetwork(){return vpnNetwork()!=null;}
    private Network vpnNetwork(){
        for(Network n:cm().getAllNetworks()){
            NetworkCapabilities c=cm().getNetworkCapabilities(n);if(c==null||!c.hasTransport(NetworkCapabilities.TRANSPORT_VPN))continue;
            LinkProperties lp=cm().getLinkProperties(n);if(lp!=null)for(LinkAddress a:lp.getLinkAddresses())if(a.getPrefixLength()==32&&"10.253.0.1".equals(a.getAddress().getHostAddress()))return n;
        }
        return null;
    }
    private void run(Intent intent){
        String stage="preflight";boolean captured=false;
        try{
            if(Build.VERSION.SDK_INT<29||!dnsOff()||VpnService.prepare(this)!=null||!RootlessNativeBridge.available())throw new IllegalStateException();
            underlay=initialNetwork();if(underlay==null)throw new IllegalStateException();
            boolean home=intent.getBooleanExtra("home",false);
            String homeCidr=home?intent.getStringExtra("homeCidr"):"";
            policy=new NativeAppRoutingPolicy(home?new NativeAppRoutingPolicy.Prefix(homeCidr):null,intent.getIntExtra("default",0),intent.getIntArrayExtra("categories"),intent.getIntArrayExtra("protocols"));
            stage="protection-config";
            dnsProvider=intent.getIntExtra("dnsProvider",0);dnsRole=intent.getIntExtra("dnsRole",0);
            if(dnsProvider<0||dnsProvider>=NativeProtectedDnsRelay.NAMES.length||dnsRole<0||dnsRole>1)throw new IllegalArgumentException();
            blockExternal853=intent.getBooleanExtra("blockExternal853",true);
            if(intent.getBooleanExtra("hostsEnabled",false)){
                RootBlocklistStore.Snapshot snapshot=RootBlocklistStore.current(getFilesDir());
                if(snapshot==null)throw new IllegalStateException("missing hosts snapshot");
                blocklist=Collections.unmodifiableSet(new HashSet<>(snapshot.domains));
            }
            String[] apps=intent.getStringArrayExtra("apps");int[] categories=intent.getIntArrayExtra("appCategories"),roles=intent.getIntArrayExtra("appRoles");
            if(apps==null||apps.length<1||apps.length>32||categories==null||roles==null||apps.length!=categories.length||apps.length!=roles.length)throw new IllegalArgumentException();
            Set<String> selected=new HashSet<>(Arrays.asList(apps));
            if(selected.size()!=apps.length||selected.contains(getPackageName()))throw new IllegalArgumentException();
            PackageManager pm=getPackageManager();
            for(int i=0;i<apps.length;i++){
                if(!AppUseCategories.validPackageName(apps[i]))throw new IllegalArgumentException();
                int uid=pm.getApplicationInfo(apps[i],0).uid;
                String[] shared=pm.getPackagesForUid(uid);
                // Reject shared or ambiguous UID mappings: all visible packages must
                // be selected and agree; require one visible package for this pilot.
                if(shared==null||shared.length!=1||!apps[i].equals(shared[0])||uid<10000||owners.containsKey(uid))throw new IllegalArgumentException();
                owners.put(uid,new NativeAppRoutingPolicy.App(categories[i],roles[i]));
            }
            stage="bootstrap";
            String[] addresses=new String[3],configs=null;
            NativeEndpointBootstrap resolver=new NativeEndpointBootstrap(this,underlay);bootstrap=resolver;
            try{
                configs=NativePeerProfiles.prepare(this,home,intent.getStringArrayExtra("overrides"),addresses,resolver,false);
                report(resolver.summary());
                if(stopping||!dnsOff()||!underlay.equals(initialNetwork()))throw new IllegalStateException();
                count=configs.length;
                for(int i=0;i<count;i++)rewrite[i]=new MultiTunnelIpv4Rewriter("10.253.0.1",addresses[i]);
                stage="native-registration";
                if(!RootlessNativeBridge.setVpnService(this))throw new IllegalStateException();registered=true;
                for(int i=0;i<count;i++){
                    stage="native-"+NativePeerProfiles.IDS[i];
                    long h=RootlessNativeBridge.createRouteSession(NativePeerProfiles.IDS[i],configs[i],addresses[i],i==2?homeCidr:"");
                    if(h<=0){stage+="/code-"+h;throw new IllegalStateException();}
                    handles[i]=h;configs[i]=null;
                }
            }finally{resolver.close();bootstrap=null;if(configs!=null)Arrays.fill(configs,null);}
            stage="handshakes";
            long deadline=SystemClock.elapsedRealtime()+60000;
            while(!stopping){
                if(!dnsOff()||!underlay.equals(initialNetwork())||!protectedSockets())throw new IllegalStateException();
                if(ready())break;
                if(SystemClock.elapsedRealtime()>=deadline)throw new IllegalStateException();
                Thread.sleep(250);
            }
            if(stopping)return;
            stage="establish";
            Builder builder=new Builder().setSession("Wonhee selected apps").setMtu(1280).setBlocking(false)
                .addAddress("10.253.0.1",32).addRoute("0.0.0.0",0)
                .addAddress("fd00:776f:6e68:6565::1",128).addRoute("::",0)
                .addDnsServer("1.1.1.1").setUnderlyingNetworks(new Network[]{underlay});
            // Capture the service UID as well for VPN Network visibility; no
            // ordinary service-owned flows are admitted by the UID ledger.
            builder.addAllowedApplication(getPackageName());
            if(home){String[] parts=homeCidr.split("/",-1);builder.addRoute(parts[0],Integer.parseInt(parts[1]));}
            for(String app:apps)builder.addAllowedApplication(app);
            tun=builder.establish();if(tun==null)throw new IllegalStateException();captured=true;
            stage="vpn-visible";
            long visibleUntil=SystemClock.elapsedRealtime()+8000;
            while(!stopping&&!ownNetwork()){if(SystemClock.elapsedRealtime()>visibleUntil)throw new IllegalStateException();Thread.sleep(50);}
            if(stopping)return;
            stage="dns-relay";
            Network vpn=vpnNetwork();if(vpn==null)throw new IllegalStateException();
            dnsRelay=new NativeProtectedDnsRelay(vpn,dnsProvider,dnsRole,blocklist);
            stage="forwarding";report("ACTIVE — "+count+" verified peers; "+apps.length+" selected apps; authenticated DoT via "+NativePeerProfiles.SLOTS[dnsRole]+"; hosts="+blocklist.size()+"; IPv6 blocked");
            long nextReport=0,nextHealth=0;
            while(!stopping){
                long now=SystemClock.elapsedRealtime();
                if(now>=nextHealth){
                    if(!dnsOff()||!physical(underlay)||!ownNetwork()||!protectedSockets()||!ready())throw new IllegalStateException();
                    nextHealth=now+1000;
                }
                if(guardTest){stage="controlled-guard-test";throw new IllegalStateException();}
                pump(now);
                if(now>=nextReport){report(stats("ACTIVE"));nextReport=now+2000;}
                Thread.sleep(2);
            }
        }catch(Exception|LinkageError failure){
            if(!stopping){
                String why=failure instanceof NativePeerProfiles.Rejected?((NativePeerProfiles.Rejected)failure).code:failure.getClass().getSimpleName();
                if(captured){
                    if(dnsRelay!=null)dnsRelay.close();
                    if(!closePeers())cleanupFailed=true;
                    report(stats("BLOCKED — "+stage+"/"+why+"; captured apps held in TUN until Stop"));
                    // Keep the default routes in the established VPN; discard rather
                    // than silently release selected applications to direct Internet.
                    long nextBlockedReport=0;
                    while(!stopping){
                        long now=SystemClock.elapsedRealtime();if(now>=nextBlockedReport){publishMetrics("BLOCKED");nextBlockedReport=now+2000;}
                        try{Os.read(tun.getFileDescriptor(),buffer,0,buffer.length);}catch(Exception ignored){}
                        try{Thread.sleep(10);}catch(InterruptedException ignored){}
                    }
                }else report("NOT STARTED — "+stage+"/"+why+"; selected apps were not captured");
            }
        }finally{
            if(dnsRelay!=null)dnsRelay.close();
            boolean ok=closePeers()&&!cleanupFailed;if(tun!=null){try{tun.close();}catch(Exception e){ok=false;}tun=null;}
            if(stopping||captured)report(stats(ok?"STOPPED — peer sessions released; TUN closed; normal networking resumes":"STOPPED — cleanup unconfirmed"));
            serviceRunning=false;
            stopForeground(STOP_FOREGROUND_REMOVE);stopSelf();
        }
    }
    private boolean protectedSockets(){long[] p=RootlessNativeBridge.protectionStats();return p!=null&&p.length>=2&&p[0]==2L*count&&p[1]==0;}
    private boolean ready(){
        for(int i=0;i<count;i++){
            long[] s=RootlessNativeBridge.peerStats(handles[i]);if(s==null||s.length<3||s[0]<=0||s[1]<=0||s[2]<=0||System.currentTimeMillis()/1000L-s[0]>240)return false;
        }return true;
    }
    private int uid(NativeAppRoutingPolicy.Key key){
        try{
            InetAddress local=InetAddress.getByAddress(new byte[]{10,(byte)253,0,1});
            int r=key.remote;
            InetAddress remote=InetAddress.getByAddress(new byte[]{(byte)(r>>>24),(byte)(r>>>16),(byte)(r>>>8),(byte)r});
            int uid=cm().getConnectionOwnerUid(key.proto,new InetSocketAddress(local,key.localPort),new InetSocketAddress(remote,key.remotePort));
            if(owners.containsKey(uid))return uid;
            if(uid==android.os.Process.myUid()&&dnsRelay!=null&&dnsRelay.owns(key))return RELAY_UID;
            // Android resolver may own the DNS socket rather than selected app.
            // Only the fixed in-tunnel DNS server has a resolver exception.
            if(key.fixedDns()&&(uid<0||uid<10000))return UNKNOWN_DNS;
        }catch(Exception ignored){}
        return -1;
    }
    private void pump(long now)throws Exception{
        ledger.sweep(now);
        for(int k=0;k<64;k++){
            int n;try{n=Os.read(tun.getFileDescriptor(),buffer,0,buffer.length);}catch(ErrnoException e){if(e.errno==OsConstants.EAGAIN)break;throw e;}
            if(n<=0)throw new IllegalStateException();
            byte[] p=Arrays.copyOf(buffer,n);
            NativeAppRoutingPolicy.Key key=NativeAppRoutingPolicy.key(p,false);
            if(key==null){unsupported++;if((p[0]&0xf0)==0x60)ipv6Drops++;else otherUnsupported++;continue;}
            NativeAppRoutingPolicy.Owner prior=ledger.get(key,now);
            boolean syn=NativeAppRoutingPolicy.syn(p);
            int owner=prior!=null&&key.proto==6&&!syn?prior.uid:uid(key);
            if(owner==-1){unknown++;continue;}
            if(key.remotePort==53){
                if(key.fixedDns()&&key.proto==17&&dnsRelay!=null&&policy.choose(key,owners.get(owner),owner==UNKNOWN_DNS)>=0){
                    dnsRelay.submit(p);continue;
                }
                dnsFirewallDrops++;continue;
            }
            if(owner!=RELAY_UID&&key.remotePort==853&&blockExternal853){dnsFirewallDrops++;continue;}
            int role=owner==RELAY_UID&&dnsRelay!=null&&dnsRelay.owns(key)?dnsRelay.role:policy.choose(key,owners.get(owner),owner==UNKNOWN_DNS);
            if(role<0||role>=count){policyDrop++;if(owner==RELAY_UID)relayEnded++;else deniedRoute++;continue;}
            byte[] translated=rewrite[role].toSession(p);
            if(translated==null){unsupported++;continue;}
            NativeAppRoutingPolicy.Owner admitted=ledger.admit(key,syn,owner,role,now);
            if(admitted==null){policyDrop++;deniedLedger++;continue;}
            int result=RootlessNativeBridge.injectPacket(handles[role],translated);
            if(result==-4){queueDrop++;continue;}if(result!=1){policyDrop++;deniedNative++;continue;}
            if(prior==null)opened[role]++;
            outgoing[role]++;outBytes[role]+=n;
        }
        if(dnsRelay!=null)for(int k=0;k<64;k++){
            byte[] response=dnsRelay.poll();if(response==null)break;
            try{if(Os.write(tun.getFileDescriptor(),response,0,response.length)!=response.length)throw new IllegalStateException();}
            catch(ErrnoException e){if(e.errno==OsConstants.EAGAIN){queueDrop++;continue;}throw e;}
        }
        for(int i=0;i<count;i++)for(int k=0;k<64;k++){
            int n=RootlessNativeBridge.pollRoutePacket(handles[i],buffer);
            if(n==0)break;if(n==-4){foreignReply++;continue;}if(n<0)throw new IllegalStateException();
            byte[] p=rewrite[i].toTun(Arrays.copyOf(buffer,n));
            NativeAppRoutingPolicy.Key key=NativeAppRoutingPolicy.key(p,true);
            if(key==null||!ledger.reply(key,i,now)){foreignReply++;continue;}
            try{if(Os.write(tun.getFileDescriptor(),p,0,p.length)!=p.length)throw new IllegalStateException();}
            catch(ErrnoException e){if(e.errno==OsConstants.EAGAIN){queueDrop++;continue;}throw e;}
            incoming[i]++;inBytes[i]+=p.length;
        }
    }
    private boolean closePeers(){
        boolean ok=true;
        for(int i=handles.length-1;i>=0;i--)if(handles[i]>0){
            try{if(!RootlessNativeBridge.closeSession(handles[i]))ok=false;}catch(Exception|LinkageError e){ok=false;}handles[i]=0;
        }
        if(registered){try{if(!RootlessNativeBridge.clearVpnService(this))ok=false;}catch(Exception|LinkageError e){ok=false;}registered=false;}
        return ok;
    }
    private String stats(String prefix){
        StringBuilder b=new StringBuilder(prefix);
        for(int i=0;i<count;i++)b.append("\n").append(NativePeerProfiles.SLOTS[i]).append(" new flows=").append(opened[i]).append(" packets out/in=").append(outgoing[i]).append('/').append(incoming[i]).append(" bytes out/in=").append(outBytes[i]).append('/').append(inBytes[i]);
        if(dnsRelay!=null)b.append("\nDNS provider=").append(NativeProtectedDnsRelay.NAMES[dnsProvider]).append(" role=").append(NativePeerProfiles.SLOTS[dnsRole]).append(" queries=").append(dnsRelay.queries.get()).append(" authenticated=").append(dnsRelay.verified.get()).append(" blocked=").append(dnsRelay.blocked.get()).append(" failed=").append(dnsRelay.failed.get()).append(" overflow=").append(dnsRelay.overflow.get()).append(" hosts=").append(blocklist.size());
        b.append("\nDNS firewall drops=").append(dnsFirewallDrops).append(" IPv6 drops=").append(ipv6Drops).append(" other unsupported=").append(otherUnsupported);
        b.append("\npolicy classification route=").append(deniedRoute).append(" ledger=").append(deniedLedger).append(" native=").append(deniedNative).append(" relay port no longer registered=").append(relayEnded);
        return b.append("\nactive tuples=").append(ledger.entries.size()).append(" unknown UID drops=").append(unknown).append(" policy drops=").append(policyDrop).append(" unsupported drops=").append(unsupported).append(" foreign reply drops=").append(foreignReply).append(" queue drops=").append(queueDrop).toString();
    }
    private void report(String s){
        Log.i(TAG,s);getSharedPreferences(PREFS,MODE_PRIVATE).edit().putString("status",s).apply();
        String state=s.startsWith("ACTIVE")?"ACTIVE":s.startsWith("BLOCKED")?"BLOCKED":s.startsWith("STOPPED")?"STOPPED":s.startsWith("NOT STARTED")?"FAILED":"STARTING";
        publishMetrics(state);
    }
    private void publishMetrics(String state){
        long now=SystemClock.elapsedRealtime(),out=0,in=0;
        for(int i=0;i<count;i++){out+=outBytes[i];in+=inBytes[i];}
        if(state.equals("ACTIVE")&&lastSample>0){upRate=NativeRoutingMetrics.perSecond(lastOut,out,now-lastSample);downRate=NativeRoutingMetrics.perSecond(lastIn,in,now-lastSample);}else{upRate=0;downRate=0;}
        lastSample=now;lastOut=out;lastIn=in;
        long blocked=dnsRelay==null?0:dnsRelay.blocked.get();
        getSharedPreferences(PREFS,MODE_PRIVATE).edit().putString("state",state).putLong("heartbeat",now).putLong("upRate",upRate).putLong("downRate",downRate).putLong("blocked",blocked).apply();
        notificationLine=state.equals("ACTIVE")?"↓ "+NativeRoutingMetrics.rate(downRate)+"  ↑ "+NativeRoutingMetrics.rate(upRate)+"  ·  blocked "+blocked:state.equals("BLOCKED")?"Traffic blocked · Stop to release":state.equals("STARTING")?"Connecting · selected apps not yet protected":state;
        if(state.equals("ACTIVE")||state.equals("BLOCKED")||state.equals("STARTING")){
            NotificationManager manager=getSystemService(NotificationManager.class);
            if(manager!=null)try{manager.notify(8402,notification());}catch(SecurityException ignored){}
        }
    }
    private Notification notification(){
        NotificationManager m=getSystemService(NotificationManager.class);
        if(m!=null)m.createNotificationChannel(new NotificationChannel(TAG,"Selected app routing",NotificationManager.IMPORTANCE_LOW));
        PendingIntent open=PendingIntent.getActivity(this,8402,new Intent(this,NativeAppRoutingActivity.class),PendingIntent.FLAG_IMMUTABLE|PendingIntent.FLAG_UPDATE_CURRENT);
        PendingIntent stop=PendingIntent.getService(this,8403,new Intent(this,NativeAppRoutingService.class).setAction(STOP),PendingIntent.FLAG_IMMUTABLE|PendingIntent.FLAG_UPDATE_CURRENT);
        return new Notification.Builder(this,TAG).setSmallIcon(R.drawable.ic_vpn_status).setContentTitle("Wonhee Proxy · selected apps").setContentText(notificationLine).setStyle(new Notification.BigTextStyle().bigText(notificationLine)).setOnlyAlertOnce(true).setContentIntent(open).addAction(new Notification.Action.Builder(null,"Stop",stop).build()).setOngoing(true).build();
    }
}
