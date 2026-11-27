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
    static final String RECOVERY_TEST="com.yooshastan.wonheeproxy.APP_ROUTE_RECOVERY_TEST";
    private volatile boolean guardTest,recoveryTest;
    static final String ISOLATION_TEST="com.yooshastan.wonheeproxy.APP_ROUTE_ISOLATION_TEST";
    private final java.util.concurrent.atomic.AtomicInteger isolationRequest=new java.util.concurrent.atomic.AtomicInteger(-2);
    private int isolationRole=-1;
    private long isolationUntil;
    private final long[] isolationOut=new long[3],isolationIn=new long[3];
    private final long[][] categoryFlows=new long[AppUseCategories.LABELS.length][3];
    static final String DNS_TEST="com.yooshastan.wonheeproxy.APP_ROUTE_DNS_TEST";
    private final AtomicBoolean dnsTest=new AtomicBoolean(),functionalTest=new AtomicBoolean();
    static final String DNS_FUNCTIONAL_TEST="com.yooshastan.wonheeproxy.APP_ROUTE_DNS_FUNCTIONAL_TEST";
    private volatile boolean autoRecovery=true;
    private int networkPreference=NativeUnderlayPolicy.WIFI_FIRST;
    private final NativeUnderlayPolicy.Debounce migration=new NativeUnderlayPolicy.Debounce();
    private final AtomicBoolean networkDirty=new AtomicBoolean(true);
    private volatile Network systemBest;
    private ConnectivityManager.NetworkCallback physicalCallback,bestCallback;
    private volatile boolean callbacksRegistered,bestRegistered;
    private long networkMigrations,lastRecoveryMs,recoveryStarted;
    private String lastRecoveryReason="none";
    private Network recoveryFrom;
    private String lastVerifiedUnderlay="none";
    private long recoveryAttempts,recoverySuccess,recoveryDiscard,priorBlocked;
    private int dnsGeneration;
    private String retiredDnsStats="";
    private String[] sessionConfigs,sessionAddresses;
    private String sessionHomeCidr="";
    private static final int MAX_RECOVERY_ATTEMPTS=5;
    private static volatile boolean serviceRunning;
    static boolean running(){return serviceRunning;}
    private long lastSample,lastOut,lastIn,upRate,downRate;
    private long deniedRoute,deniedLedger,deniedNative,relayEnded;
    private String notificationLine="Connecting…";
    private NativeProtectedDnsRelay dnsRelay;
    private long dnsFirewallDrops,ipv6Drops,otherUnsupported,unsupportedIpv4TcpUdp,unsupportedIpv4Other,unsupportedVersion,unknownTcp,unknownUdp,unknownDns;
    private boolean blockExternal853,allApps;
    private final Map<String,NativeAppRoutingPolicy.App> packageRules=new HashMap<>();
    private final long[][] portFlows=new long[NativeAppRoutingPolicy.SELECTORS.length][3];
    private int dnsProvider,dnsRole,dnsMode,dnsAlternate;
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
    private volatile Network underlay;
    private NativeAppRoutingPolicy policy;
    private int count;
    private final byte[] buffer=new byte[1280];
    @Override public int onStartCommand(Intent intent,int flags,int id){
        String action=intent==null?null:intent.getAction();
        if(DNS_FUNCTIONAL_TEST.equals(action)){if(started.get())functionalTest.set(true);else stopSelf();return START_NOT_STICKY;}
        if(DNS_TEST.equals(action)){if(started.get())dnsTest.set(true);else stopSelf();return START_NOT_STICKY;}
        if(RECOVERY_TEST.equals(action)){if(started.get()&&autoRecovery)recoveryTest=true;else if(!started.get())stopSelf();return START_NOT_STICKY;}
        if(ISOLATION_TEST.equals(action)){if(started.get())isolationRequest.set(intent.getIntExtra("role",-1));else stopSelf();return START_NOT_STICKY;}
        if(GUARD_TEST.equals(action)){if(started.get())guardTest=true;else stopSelf();return START_NOT_STICKY;}
        if(STOP.equals(action)){requestStop();if(!started.get())stopSelf();return START_NOT_STICKY;}
        if(!START.equals(action)){if(!started.get())stopSelf();return START_NOT_STICKY;}
        if(!started.compareAndSet(false,true))return START_NOT_STICKY;
        serviceRunning=true;
        Notification n=notification();
        if(Build.VERSION.SDK_INT>=34)startForeground(8402,n,ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);else startForeground(8402,n);
        report("STARTING — apps are not captured until VPN establishment");
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
    private boolean noVpn(){
        for(Network n:cm().getAllNetworks()){NetworkCapabilities c=cm().getNetworkCapabilities(n);if(c!=null&&c.hasTransport(NetworkCapabilities.TRANSPORT_VPN))return false;}
        return true;
    }
    private Network initialNetwork(){return noVpn()?preferredNetwork():null;}
    private boolean ownNetwork(){return vpnNetwork()!=null;}
    // JNI invokes this virtual method before exposing either WireGuard socket.
    // Duplicate the descriptor; binding/closing the duplicate does not close the native socket.
    @Override public boolean protect(int fd){
        Network n=underlay;
        if(stopping||!physical(n)||!super.protect(fd))return false;
        try(ParcelFileDescriptor copy=ParcelFileDescriptor.fromFd(fd)){
            n.bindSocket(copy.getFileDescriptor());
            return n.equals(underlay)&&physical(n)&&!stopping;
        }catch(Exception failure){return false;}
    }
    private boolean usable(Network n){
        NetworkCapabilities c=n==null?null:cm().getNetworkCapabilities(n);
        return physical(n)&&c!=null&&c.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            &&c.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            &&c.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            &&c.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
            &&c.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_SUSPENDED);
    }
    private static long id(Network n){return n==null?0:n.getNetworkHandle();}
    private Network preferredNetwork(){
        Map<Long,Integer> candidates=new HashMap<>();
        Map<Long,Network> networks=new HashMap<>();
        for(Network n:cm().getAllNetworks())if(usable(n)){
            NetworkCapabilities c=cm().getNetworkCapabilities(n);if(c==null)continue;
            long key=id(n);
            candidates.put(key,c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)?NativeUnderlayPolicy.WIFI:NativeUnderlayPolicy.CELL);
            networks.put(key,n);
        }
        Network best=systemBest;
        if(best==null){Network active=cm().getActiveNetwork();if(usable(active))best=active;}
        return networks.get(NativeUnderlayPolicy.pick(networkPreference,id(underlay),id(best),candidates));
    }
    private void watchNetworks(){
        NetworkRequest request=new NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI).addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR).build();
        physicalCallback=new ConnectivityManager.NetworkCallback(){
            @Override public void onAvailable(Network n){networkDirty.set(true);}
            @Override public void onLost(Network n){networkDirty.set(true);}
            @Override public void onCapabilitiesChanged(Network n,NetworkCapabilities c){networkDirty.set(true);}
        };
        try{cm().registerNetworkCallback(request,physicalCallback);callbacksRegistered=true;}
        catch(RuntimeException e){Log.i(TAG,"UNDERLAY WATCH — callback unavailable; polling retained");}
        if(Build.VERSION.SDK_INT>=31&&networkPreference==NativeUnderlayPolicy.SYSTEM){
            // Best physical match, not the app's VPN default. VALIDATED is a
            // listen-only capability; suitability is rechecked by the worker.
            bestCallback=new ConnectivityManager.NetworkCallback(){
                @Override public void onAvailable(Network n){systemBest=n;networkDirty.set(true);}
                @Override public void onLost(Network n){if(n.equals(systemBest))systemBest=null;networkDirty.set(true);}
                @Override public void onCapabilitiesChanged(Network n,NetworkCapabilities c){networkDirty.set(true);}
            };
            try{cm().registerBestMatchingNetworkCallback(request,bestCallback,new Handler(Looper.getMainLooper()));bestRegistered=true;}
            catch(RuntimeException e){Log.i(TAG,"UNDERLAY WATCH — best match unavailable; physical default/sticky fallback");}
        }
    }
    private void unwatchNetworks(){
        if(callbacksRegistered){try{cm().unregisterNetworkCallback(physicalCallback);}catch(RuntimeException ignored){}callbacksRegistered=false;}
        if(bestRegistered){try{cm().unregisterNetworkCallback(bestCallback);}catch(RuntimeException ignored){}bestRegistered=false;}
        systemBest=null;
    }
    private String physicalLabel(Network n){
        if(n==null)return "none";
        NetworkCapabilities c=cm().getNetworkCapabilities(n);
        String type=c==null?"unavailable":c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)?"Wi-Fi":c.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)?"Cellular":"other";
        return type+" #"+n.toString()+" ("+(usable(n)?"validated":"not validated")+")";
    }
    private String underlaySummary(){
        return "underlay="+physicalLabel(underlay)+" preference="+NativeUnderlayPolicy.LABELS[networkPreference]
            +" network migrations="+networkMigrations+" last recovery reason="+lastRecoveryReason+" last recovery ms="+lastRecoveryMs
            +" physical callback="+callbacksRegistered+" system best callback="+bestRegistered
            +" last verified underlay="+lastVerifiedUnderlay;
    }
    private boolean captureIntact(){return tun!=null&&ownNetwork()&&VpnService.prepare(this)==null;}
    private void discardCaptured(){
        if(tun==null)return;
        for(int k=0;k<128;k++){
            try{int n=Os.read(tun.getFileDescriptor(),buffer,0,buffer.length);if(n<=0)break;recoveryDiscard++;}
            catch(Exception ignored){break;}
        }
    }
    private void retireDns(){
        NativeProtectedDnsRelay old=dnsRelay;
        if(old==null)return;
        old.close();
        if(!old.awaitStopped())cleanupFailed=true;
        priorBlocked+=old.blocked.get();
        retiredDnsStats="last DNS generation="+dnsGeneration+" queries="+old.queries.get()+" authenticated="+old.verified.get()+" blocked="+old.blocked.get()+" failed="+old.failed.get()+" overflow="+old.overflow.get()+" TLS opened="+old.tlsConnections.get()+" TLS closed="+old.tlsClosed.get();
        dnsRelay=null;
    }
    private void newRelay()throws Exception{
        Network vpn=vpnNetwork();if(vpn==null)throw new IllegalStateException();
        dnsRelay=new NativeProtectedDnsRelay(vpn,dnsProvider,dnsRole,dnsMode,dnsAlternate,blocklist);dnsGeneration++;
    }
    private void createPeers()throws Exception{
        if(stopping||!dnsOff()||!physical(underlay)||sessionConfigs==null)throw new IllegalStateException();
        count=sessionConfigs.length;
        if(!RootlessNativeBridge.setVpnService(this))throw new IllegalStateException();registered=true;
        for(int i=0;i<count;i++){
            rewrite[i]=new MultiTunnelIpv4Rewriter("10.253.0.1",sessionAddresses[i]);
            long h=RootlessNativeBridge.createRouteSession(NativePeerProfiles.IDS[i],sessionConfigs[i],sessionAddresses[i],i==2?sessionHomeCidr:"");
            if(h<=0)throw new IllegalStateException("peer creation rejected");
            handles[i]=h;
        }
    }
    private boolean recover()throws InterruptedException{
        if(!autoRecovery||guardTest||cleanupFailed||!captureIntact())return false;
        for(int attempt=0;attempt<MAX_RECOVERY_ATTEMPTS&&!stopping&&!guardTest;attempt++){
            long wait=NativeRecoveryPlan.delay(attempt),until=SystemClock.elapsedRealtime()+wait;
            report(stats("RECOVERING — selected apps held in existing TUN; retry "+(attempt+1)+"/"+MAX_RECOVERY_ATTEMPTS));
            while(SystemClock.elapsedRealtime()<until&&!stopping&&!guardTest){
                if(!captureIntact())return false;discardCaptured();Thread.sleep(50);
            }
            if(stopping||guardTest||!captureIntact()||!dnsOff())return false;
            recoveryAttempts++;
            Network next=preferredNetwork();
            if(next==null)continue;
            underlay=next;
            try{
                if(!setUnderlyingNetworks(new Network[]{next}))throw new IllegalStateException();
                createPeers();
                long deadline=SystemClock.elapsedRealtime()+60000;
                while(!stopping&&!guardTest){
                    if(!captureIntact()||!dnsOff()||!usable(next)||!protectedSockets())throw new IllegalStateException();
                    discardCaptured();
                    if(ready())break;
                    if(SystemClock.elapsedRealtime()>=deadline)throw new IllegalStateException();
                    Thread.sleep(100);
                }
                if(stopping||guardTest||!captureIntact()||!dnsOff()||!usable(next)||!ready())throw new IllegalStateException();
                discardCaptured();
                ledger.entries.clear();
                newRelay();
                recoverySuccess++;
                if(recoveryFrom!=null&&!recoveryFrom.equals(next))networkMigrations++;
                lastRecoveryMs=SystemClock.elapsedRealtime()-recoveryStarted;
                lastVerifiedUnderlay=physicalLabel(next);migration.reset();
                report(stats("ACTIVE — recovery verified; same TUN retained; "+lastRecoveryReason+"; "+lastRecoveryMs+" ms"));
                return true;
            }catch(Exception|LinkageError failure){
                retireDns();if(!closePeers())cleanupFailed=true;
                if(cleanupFailed)return false;
                report(stats("RECOVERING — attempt refused; forwarding remains disabled"));
                if(failure instanceof InterruptedException)throw (InterruptedException)failure;
            }
        }
        return false;
    }
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
            if(Build.VERSION.SDK_INT<29){stage="preflight/API_UNSUPPORTED";throw new IllegalStateException();}
            if(!dnsOff()){stage="preflight/PRIVATE_DNS_NOT_OFF";throw new IllegalStateException();}
            if(VpnService.prepare(this)!=null){stage="preflight/VPN_PERMISSION_REQUIRED";throw new IllegalStateException();}
            if(!RootlessNativeBridge.available()){stage="preflight/NATIVE_LIBRARY_LOAD_FAILED";throw new IllegalStateException();}
            autoRecovery=intent.getBooleanExtra("autoRecovery",true);
            networkPreference=intent.getIntExtra("networkPreference",NativeUnderlayPolicy.WIFI_FIRST);
            if(!NativeUnderlayPolicy.valid(networkPreference)){networkPreference=NativeUnderlayPolicy.WIFI_FIRST;throw new IllegalArgumentException();}
            watchNetworks();
            underlay=initialNetwork();if(underlay==null){stage=noVpn()?"preflight/NO_VALIDATED_PHYSICAL_NETWORK (check connectivity or firewall)":"preflight/EXISTING_VPN_ACTIVE";throw new IllegalStateException();}
            boolean home=intent.getBooleanExtra("home",false);
            String homeCidr=home?intent.getStringExtra("homeCidr"):"";sessionHomeCidr=homeCidr;
            policy=new NativeAppRoutingPolicy(home?new NativeAppRoutingPolicy.Prefix(homeCidr):null,intent.getIntExtra("default",0),intent.getIntArrayExtra("categories"),intent.getIntArrayExtra("protocols"));
            stage="protection-config/DNS_SELECTION";
            dnsProvider=intent.getIntExtra("dnsProvider",0);dnsRole=intent.getIntExtra("dnsRole",0);dnsMode=intent.getIntExtra("dnsMode",0);dnsAlternate=intent.getIntExtra("dnsAlternate",0);
            if(!NativeDnsTransportPolicy.supports(dnsProvider,dnsMode)||dnsRole<0||dnsRole>1||dnsAlternate<0||dnsAlternate>1)throw new IllegalArgumentException();
            blockExternal853=intent.getBooleanExtra("blockExternal853",true);
            stage="protection-config/HOSTS";
            if(intent.getBooleanExtra("hostsEnabled",false)){
                RootBlocklistStore.Snapshot snapshot=RootBlocklistStore.current(getFilesDir());
                if(snapshot==null)throw new IllegalStateException("missing hosts snapshot");
                blocklist=Collections.unmodifiableSet(new HashSet<>(snapshot.domains));
            }
            stage="app-config";
            allApps=intent.getBooleanExtra("allApps",false);
            String[] apps=intent.getStringArrayExtra("apps");int[] categories=intent.getIntArrayExtra("appCategories"),roles=intent.getIntArrayExtra("appRoles");
            if(apps==null||(!allApps&&apps.length<1)||apps.length>512||categories==null||roles==null||apps.length!=categories.length||apps.length!=roles.length)throw new NativePeerProfiles.Rejected("INVALID_APP_RULE_ARRAYS_OR_LIMIT");
            Set<String> selected=new HashSet<>(Arrays.asList(apps));
            if(selected.size()!=apps.length||selected.contains(getPackageName()))throw new NativePeerProfiles.Rejected("DUPLICATE_OR_SELF_APP_RULE");
            PackageManager pm=getPackageManager();
            for(int i=0;i<apps.length;i++){
                if(!AppUseCategories.validPackageName(apps[i]))throw new NativePeerProfiles.Rejected("INVALID_PACKAGE_RULE");
                NativeAppRoutingPolicy.App assignment=new NativeAppRoutingPolicy.App(categories[i],roles[i]);
                packageRules.put(apps[i],assignment);
            }
            if(!allApps)for(String app:apps){
                int uid=pm.getApplicationInfo(app,0).uid;
                String[] shared=pm.getPackagesForUid(uid);
                if(uid<10000||uid==android.os.Process.myUid()||shared==null||shared.length==0||shared.length>512)throw new NativePeerProfiles.Rejected("SELECTED_UID_UNSUPPORTED_USE_ALL_APP_MODE");
                NativeAppRoutingPolicy.App assignment=packageRules.get(app);
                for(String member:shared){
                    if(!selected.contains(member)||pm.getApplicationInfo(member,0).uid!=uid||!assignment.same(packageRules.get(member)))
                        throw new NativePeerProfiles.Rejected("SHARED_UID_REQUIRES_ALL_MEMBERS_SAME_RULE_OR_ALL_APP_MODE");
                }
                owners.put(uid,assignment);
            }
            Log.i(TAG,"PREFLIGHT — "+(allApps?"all-app capture; explicit rules=":"selected-app capture; packages=")+apps.length+"; validated UID groups="+owners.size()+"; bootstrap="+intent.getIntExtra("bootstrapOption",0));
            stage="bootstrap";
            String[] addresses=new String[3],configs=null;
            NativeEndpointBootstrap resolver=new NativeEndpointBootstrap(this,underlay,intent.getIntExtra("bootstrapOption",0));bootstrap=resolver;
            try{
                configs=NativePeerProfiles.prepare(this,home,intent.getStringArrayExtra("overrides"),addresses,resolver,false);
                report(resolver.summary());
                if(stopping||!dnsOff()||!usable(underlay)||!noVpn())throw new IllegalStateException();
                // Immutable session snapshot: recovery cannot silently load a newly
                // imported profile or change a resolved endpoint. No disk persistence.
                sessionConfigs=configs.clone();sessionAddresses=addresses.clone();
                stage="native-registration";
                createPeers();
            }finally{resolver.close();bootstrap=null;if(configs!=null)Arrays.fill(configs,null);}
            stage="handshakes";
            long deadline=SystemClock.elapsedRealtime()+60000;
            while(!stopping){
                if(!dnsOff()||!usable(underlay)||!noVpn()||!protectedSockets())throw new IllegalStateException();
                if(ready())break;
                if(SystemClock.elapsedRealtime()>=deadline)throw new IllegalStateException();
                Thread.sleep(250);
            }
            if(stopping)return;
            stage="establish";
            Builder builder=new Builder().setSession(allApps?"Wonhee all-app preview":"Wonhee selected apps").setMtu(1280).setBlocking(false)
                .addAddress("10.253.0.1",32).addRoute("0.0.0.0",0)
                .addAddress("fd00:776f:6e68:6565::1",128).addRoute("::",0)
                .addDnsServer("1.1.1.1").setUnderlyingNetworks(new Network[]{underlay});
            // Capture the service UID as well for VPN Network visibility; no
            // ordinary service-owned flows are admitted by the UID ledger.
            if(!allApps)builder.addAllowedApplication(getPackageName());
            if(home){String[] parts=homeCidr.split("/",-1);builder.addRoute(parts[0],Integer.parseInt(parts[1]));}
            if(!allApps)for(String app:apps)builder.addAllowedApplication(app);
            tun=builder.establish();if(tun==null)throw new IllegalStateException();captured=true;
            stage="vpn-visible";
            long visibleUntil=SystemClock.elapsedRealtime()+8000;
            while(!stopping&&!ownNetwork()){if(SystemClock.elapsedRealtime()>visibleUntil)throw new IllegalStateException();Thread.sleep(50);}
            if(stopping)return;
            stage="dns-relay";
            newRelay();
            lastVerifiedUnderlay=physicalLabel(underlay);
            stage="forwarding";report("ACTIVE — "+count+" verified peers; "+(allApps?"all-app preview":apps.length+" selected apps")+"; configured "+NativeDnsTransportPolicy.LABELS[dnsMode]+" via "+NativePeerProfiles.SLOTS[dnsRole]+"; hosts="+blocklist.size()+"; IPv6 blocked");
            long nextReport=0,nextHealth=0;
            while(!stopping){
                long now=SystemClock.elapsedRealtime();
                String reason=null;
                if(now>=nextHealth||networkDirty.getAndSet(false)){
                    if(!dnsOff()){stage="private-dns-changed";throw new IllegalStateException();}
                    if(!captureIntact()){stage="vpn-capture-lost";throw new IllegalStateException();}
                    if(!usable(underlay))reason="physical-underlay-lost";
                    else if(!protectedSockets()||!ready())reason="peer-health";
                    else if(autoRecovery){
                        Network candidate=preferredNetwork();
                        if(migration.due(id(underlay),id(candidate),now))reason="preferred-network-migration";
                    }
                    nextHealth=now+1000;
                }
                if(guardTest){stage="controlled-guard-test";throw new IllegalStateException();}
                int request=isolationRequest.getAndSet(-2);
                if(request==-1||(isolationRole>=0&&now>=isolationUntil)){
                    isolationRole=-1;isolationUntil=0;Log.i(TAG,"ISOLATION TEST — ended; normal assigned routes restored");
                }
                if(request>=0){
                    if(NativeRoutingSafety.isolationAllowed(request,count,dnsRole)){
                        isolationRole=request;isolationUntil=now+NativeRoutingSafety.ISOLATION_MS;
                        Log.i(TAG,"ISOLATION TEST — holding "+NativePeerProfiles.SLOTS[request]+" for 30 seconds; no reroute");
                    }else Log.i(TAG,"ISOLATION TEST — refused: inactive slot or configured DNS exit");
                }
                if(recoveryTest||reason!=null){
                    stage=recoveryTest?"controlled-recovery-test":reason;recoveryTest=false;
                    isolationRole=-1;isolationUntil=0;
                    lastRecoveryReason=stage;recoveryStarted=SystemClock.elapsedRealtime();recoveryFrom=underlay;
                    migration.reset();
                    report(stats("RECOVERING — "+stage+"; stopping forwarding"));
                    retireDns();if(!closePeers())cleanupFailed=true;ledger.entries.clear();
                    if(!recover())throw new IllegalStateException("recovery unavailable");
                    stage="forwarding";nextHealth=0;nextReport=0;continue;
                }
                if(dnsTest.getAndSet(false)&&dnsRelay!=null)dnsRelay.testProvider();
                if(functionalTest.getAndSet(false)&&dnsRelay!=null)dnsRelay.testFunctional();
                pump(now);
                if(now>=nextReport){report(stats("ACTIVE"));nextReport=now+2000;}
                Thread.sleep(2);
            }
        }catch(Exception|LinkageError failure){
            if(!stopping){
                String why=failure instanceof NativePeerProfiles.Rejected?((NativePeerProfiles.Rejected)failure).code:failure.getClass().getSimpleName();
                if(captured){
                    retireDns();
                    if(!closePeers())cleanupFailed=true;
                    report(stats(captureIntact()?"BLOCKED — "+stage+"/"+why+"; captured apps held in TUN until Stop":"CAPTURE LOST — VPN visibility lost; blocking cannot be guaranteed; press Stop"));
                    // Keep the default routes in the established VPN; discard rather
                    // than silently release selected applications to direct Internet.
                    long nextBlockedReport=0;
                    while(!stopping){
                        long now=SystemClock.elapsedRealtime();if(now>=nextBlockedReport){
                            if(captureIntact())report(stats("BLOCKED — captured apps held in TUN until Stop"));
                            else report("CAPTURE LOST — VPN visibility lost; blocking cannot be guaranteed; press Stop");
                            nextBlockedReport=now+2000;
                        }
                        discardCaptured();
                        try{Thread.sleep(10);}catch(InterruptedException ignored){}
                    }
                }else report("NOT STARTED — "+stage+"/"+why+"; apps were not captured");
            }
        }finally{
            unwatchNetworks();
            retireDns();
            if(sessionConfigs!=null)Arrays.fill(sessionConfigs,null);
            if(sessionAddresses!=null)Arrays.fill(sessionAddresses,null);
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
    // Resolve a reported UID, never infer an owner from a packet or default-route an unknown UID.
    private boolean resolveOwner(int uid){
        if(uid<0||uid==android.os.Process.myUid())return false;
        if(!allApps)return owners.containsKey(uid);
        PackageManager pm=getPackageManager();
        String[] pkgs=pm.getPackagesForUid(uid);
        if(pkgs==null||pkgs.length==0||pkgs.length>512){owners.remove(uid);return false;}
        NativeAppRoutingPolicy.App common=null;
        for(String pkg:pkgs){
            NativeAppRoutingPolicy.App a=packageRules.get(pkg);
            try{
                android.content.pm.ApplicationInfo info=pm.getApplicationInfo(pkg,0);
                if(info.uid!=uid){owners.remove(uid);return false;}
                if(a==null)a=new NativeAppRoutingPolicy.App(NativeAppCategorySuggestions.suggest(pkg,info.category,(info.flags&android.content.pm.ApplicationInfo.FLAG_SYSTEM)!=0),NativeAppRoutingPolicy.INHERIT);
            }catch(Exception e){owners.remove(uid);return false;}
            if(common!=null&&!common.same(a)){owners.remove(uid);return false;}
            common=a;
        }
        if(owners.size()>=8192&&!owners.containsKey(uid))return false;
        owners.put(uid,common);return true;
    }
    private int uid(NativeAppRoutingPolicy.Key key){
        try{
            InetAddress local=InetAddress.getByAddress(new byte[]{10,(byte)253,0,1});
            int r=key.remote;
            InetAddress remote=InetAddress.getByAddress(new byte[]{(byte)(r>>>24),(byte)(r>>>16),(byte)(r>>>8),(byte)r});
            int uid=cm().getConnectionOwnerUid(key.proto,new InetSocketAddress(local,key.localPort),new InetSocketAddress(remote,key.remotePort));
            if(resolveOwner(uid))return uid;
            if(uid==android.os.Process.myUid()&&dnsRelay!=null&&dnsRelay.functionalOwns(key))return UNKNOWN_DNS;
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
            if(key==null){unsupported++;if((p[0]&0xf0)==0x60)ipv6Drops++;else{otherUnsupported++;if((p[0]&0xf0)==0x40&&p.length>=20){int proto=p[9]&255;if(proto==6||proto==17)unsupportedIpv4TcpUdp++;else unsupportedIpv4Other++;}else unsupportedVersion++;}continue;}
            NativeAppRoutingPolicy.Owner prior=ledger.get(key,now);
            boolean syn=NativeAppRoutingPolicy.syn(p);
            int owner=prior!=null&&key.proto==6&&!syn?prior.uid:uid(key);
            if(owner==-1){unknown++;if(key.proto==6)unknownTcp++;else if(key.proto==17)unknownUdp++;if(key.fixedDns())unknownDns++;continue;}
            if(key.remotePort==53){
                if(key.fixedDns()&&dnsRelay!=null&&policy.choose(key,owners.get(owner),owner==UNKNOWN_DNS)>=0){
                    if(key.proto==17){dnsRelay.submit(p);continue;}
                    if(key.proto==6&&dnsRelay.feedTcp(p))continue;
                }
                dnsFirewallDrops++;continue;
            }
            if(owner!=RELAY_UID&&key.remotePort==853&&blockExternal853){dnsFirewallDrops++;continue;}
            int role=owner==RELAY_UID&&dnsRelay!=null&&dnsRelay.owns(key)?dnsRelay.role:policy.choose(key,owners.get(owner),owner==UNKNOWN_DNS);
            if(role<0||role>=count){policyDrop++;if(owner==RELAY_UID)relayEnded++;else deniedRoute++;continue;}
            if(NativeRoutingSafety.held(role,isolationRole,now,isolationUntil)){isolationOut[role]++;continue;}
            byte[] translated=rewrite[role].toSession(p);
            if(translated==null){unsupported++;continue;}
            NativeAppRoutingPolicy.Owner admitted=ledger.admit(key,syn,owner,role,now);
            if(admitted==null){policyDrop++;deniedLedger++;continue;}
            int result=RootlessNativeBridge.injectPacket(handles[role],translated);
            if(result==-4){queueDrop++;continue;}if(result!=1){policyDrop++;deniedNative++;continue;}
            if(prior==null){
                opened[role]++;
                if(owner!=RELAY_UID){int selector=NativeAppRoutingPolicy.selector(key);if(selector>=0)portFlows[selector][role]++;NativeAppRoutingPolicy.App app=owners.get(owner);if(app!=null)categoryFlows[app.category][role]++;}
            }
            if(owner==RELAY_UID&&dnsRelay!=null&&dnsRelay.quicOwns(key))dnsRelay.quicTunTx.incrementAndGet();
            outgoing[role]++;outBytes[role]+=n;
        }
        if(dnsRelay!=null)dnsRelay.drainTcpQueries();
        if(dnsRelay!=null)for(int k=0;k<64;k++){
            byte[] response=dnsRelay.poll();if(response==null)break;
            try{if(Os.write(tun.getFileDescriptor(),response,0,response.length)!=response.length)throw new IllegalStateException();}
            catch(ErrnoException e){if(e.errno==OsConstants.EAGAIN){queueDrop++;continue;}throw e;}
        }
        for(int i=0;i<count;i++)for(int k=0;k<64;k++){
            int n=RootlessNativeBridge.pollRoutePacket(handles[i],buffer);
            if(n==0)break;if(n==-4){foreignReply++;continue;}if(n<0)throw new IllegalStateException();
            if(NativeRoutingSafety.held(i,isolationRole,now,isolationUntil)){isolationIn[i]++;continue;}
            byte[] p=rewrite[i].toTun(Arrays.copyOf(buffer,n));
            NativeAppRoutingPolicy.Key key=NativeAppRoutingPolicy.key(p,true);
            if(key==null||!ledger.reply(key,i,now)){if(dnsRelay!=null&&dnsRelay.quicOwns(key))dnsRelay.quicTunRejected.incrementAndGet();foreignReply++;continue;}
            try{if(Os.write(tun.getFileDescriptor(),p,0,p.length)!=p.length)throw new IllegalStateException();}
            catch(ErrnoException e){if(e.errno==OsConstants.EAGAIN){queueDrop++;continue;}throw e;}
            if(dnsRelay!=null&&dnsRelay.quicOwns(key)&&i==dnsRelay.role)dnsRelay.quicTunRx.incrementAndGet();
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
        b.append("\nIsolation test=").append(isolationRole>=0?NativePeerProfiles.SLOTS[isolationRole]:"off").append(" held out A/B/Home=").append(isolationOut[0]).append("/").append(isolationOut[1]).append("/").append(isolationOut[2]).append(" held in A/B/Home=").append(isolationIn[0]).append("/").append(isolationIn[1]).append("/").append(isolationIn[2]);
        for(int j=0;j<categoryFlows.length;j++)if(categoryFlows[j][0]+categoryFlows[j][1]+categoryFlows[j][2]>0)b.append("\nCategory flows ").append(AppUseCategories.LABELS[j]).append(" A/B/Home=").append(categoryFlows[j][0]).append("/").append(categoryFlows[j][1]).append("/").append(categoryFlows[j][2]);
        b.append("\nCapture mode=").append(allApps?"all-app preview":"selected apps").append(" resolved UIDs=").append(owners.size());
        for(int j=0;j<portFlows.length;j++)if(portFlows[j][0]+portFlows[j][1]+portFlows[j][2]>0)b.append("\nPort flows ").append(NativeAppRoutingPolicy.SELECTOR_NAMES[j]).append(" A/B/Home=").append(portFlows[j][0]).append("/").append(portFlows[j][1]).append("/").append(portFlows[j][2]);
        for(int i=0;i<count;i++)b.append("\n").append(NativePeerProfiles.SLOTS[i]).append(" new flows=").append(opened[i]).append(" packets out/in=").append(outgoing[i]).append('/').append(incoming[i]).append(" bytes out/in=").append(outBytes[i]).append('/').append(inBytes[i]);
        if(dnsRelay!=null)b.append("\nDNS provider=").append(NativeProtectedDnsRelay.NAMES[dnsProvider]).append(" role=").append(NativePeerProfiles.SLOTS[dnsRole]).append(" queries=").append(dnsRelay.queries.get()).append(" authenticated=").append(dnsRelay.verified.get()).append(" blocked=").append(dnsRelay.blocked.get()).append(" failed=").append(dnsRelay.failed.get()).append(" overflow=").append(dnsRelay.overflow.get()).append(" hosts=").append(blocklist.size()).append(" cache hits=").append(dnsRelay.cacheHits.get()).append(" cached entries=").append(dnsRelay.cacheSize()).append(" TLS opened=").append(dnsRelay.tlsConnections.get()).append(" TLS reused=").append(dnsRelay.tlsReuse.get()).append(" TLS fresh retries=").append(dnsRelay.tlsRetries.get()).append(" TLS closed=").append(dnsRelay.tlsClosed.get()).append(" retry EOF=").append(dnsRelay.retryEof.get()).append(" retry timeout=").append(dnsRelay.retryTimeout.get()).append(" retry TLS=").append(dnsRelay.retryTls.get()).append(" retry other=").append(dnsRelay.retryOther.get()).append(" active relay sockets=").append(dnsRelay.socketCount()).append(" registered relay ports=").append(dnsRelay.portCount()).append(" DNS transport=").append(NativeDnsTransportPolicy.LABELS[dnsMode]).append(" UDP queries=").append(dnsRelay.udpQueries.get()).append(" TCP queries=").append(dnsRelay.tcpQueries.get()).append(" TCP rejected=").append(dnsRelay.tcpRejected.get()).append(" UDP truncated=").append(dnsRelay.udpTruncated.get()).append(" QUIC opened=").append(dnsRelay.quicOpened.get()).append(" QUIC verified=").append(dnsRelay.quicVerified.get()).append(" QUIC failed=").append(dnsRelay.quicFailed.get()).append(" QUIC attempts=").append(dnsRelay.quicAttempts.get()).append(" QUIC reused=").append(dnsRelay.quicReused.get()).append(" QUIC closed=").append(dnsRelay.quicClosed.get()).append(" QUIC backoff=").append(dnsRelay.quicBackoff.get()).append(" QUIC timeout=").append(dnsRelay.quicTimeout.get()).append(" QUIC certificate=").append(dnsRelay.quicCertificate.get()).append(" QUIC socket error=").append(dnsRelay.quicSocketError.get()).append(" QUIC invalid=").append(dnsRelay.quicInvalid.get()).append(" QUIC other=").append(dnsRelay.quicOther.get()).append(" DNS coalesced=").append(dnsRelay.coalesced.get()).append(" DNS latency samples=").append(dnsRelay.dnsLatencySamples.get()).append(" DNS upstream total ms=").append(dnsRelay.dnsLatencyTotalMs.get()).append(" DNS upstream max ms=").append(dnsRelay.dnsLatencyMaxMs.get()).append(" endpoint=").append(dnsRelay.endpoint).append(" QUIC fresh retries=").append(dnsRelay.quicFreshRetries.get()).append(" QUIC retry success=").append(dnsRelay.quicRetrySuccess.get()).append(" QUIC fresh failures=").append(dnsRelay.quicFreshFailures.get()).append(" QUIC handshake timeout=").append(dnsRelay.quicHandshakeTimeout.get()).append(" endpoint port=").append(NativeDnsTransportPolicy.port(dnsMode)).append(" SNI=").append(NativeProtectedDnsRelay.HOSTS[dnsProvider]).append(" ALPN=").append(dnsMode==NativeDnsTransportPolicy.DOQ?"doq":dnsMode==NativeDnsTransportPolicy.DOH3?"h3":"n/a").append(" QUIC handshake retries=").append(dnsRelay.quicHandshakeRetries.get()).append(" QUIC handshake timeout last ms=").append(dnsRelay.quicHandshakeTimeoutLastMs.get()).append(" QUIC fresh exchange last ms=").append(dnsRelay.quicFreshExchangeLastMs.get()).append(" QUIC stream reset=").append(dnsRelay.quicStreamReset.get()).append(" QUIC remote close=").append(dnsRelay.quicRemoteClose.get()).append(" QUIC transport error=").append(dnsRelay.quicTransportError.get()).append(" QUIC TLS error=").append(dnsRelay.quicTlsError.get()).append(" QUIC socket tx=").append(dnsRelay.quicSocketTx.get()).append(" rx=").append(dnsRelay.quicSocketRx.get()).append(" tx min/max=").append(dnsRelay.quicTxMin.get()).append('/').append(dnsRelay.quicTxMax.get()).append(" rx min/max=").append(dnsRelay.quicRxMin.get()).append('/').append(dnsRelay.quicRxMax.get()).append(" write/read errors=").append(dnsRelay.quicWriteErrors.get()).append('/').append(dnsRelay.quicReadErrors.get()).append(" timeout tx/rx=").append(dnsRelay.lastTimeoutTx.get()).append('/').append(dnsRelay.lastTimeoutRx.get()).append(" QUIC TUN tx=").append(dnsRelay.quicTunTx.get()).append(" rx=").append(dnsRelay.quicTunRx.get()).append(" rejected=").append(dnsRelay.quicTunRejected.get()).append(" DNS probe attempts=").append(dnsRelay.probeAttempts.get()).append(" DNS probe passed=").append(dnsRelay.probePassed.get()).append(" DNS probe failed=").append(dnsRelay.probeFailed.get()).append(" DNS health=").append(dnsRelay.health()).append(" DNS probe=").append(dnsRelay.probeStatus()).append(" DNS functional test=").append(dnsRelay.functionalStatus());
        if(dnsRelay==null&&!retiredDnsStats.isEmpty())b.append("\n").append(retiredDnsStats);
        b.append("\n").append(underlaySummary());
        b.append("\nrecovery attempts=").append(recoveryAttempts).append(" successes=").append(recoverySuccess).append(" discarded packets=").append(recoveryDiscard).append(" DNS generation=").append(dnsGeneration).append(" session blocked=").append(priorBlocked+(dnsRelay==null?0:dnsRelay.blocked.get()));
        b.append("\nDNS firewall drops=").append(dnsFirewallDrops).append(" IPv6 drops=").append(ipv6Drops).append(" other unsupported=").append(otherUnsupported).append(" unsupported IPv4 TCP/UDP=").append(unsupportedIpv4TcpUdp).append(" unsupported IPv4 other protocol=").append(unsupportedIpv4Other).append(" unsupported version/header=").append(unsupportedVersion);
        b.append("\npolicy classification route=").append(deniedRoute).append(" ledger=").append(deniedLedger).append(" native=").append(deniedNative).append(" relay port no longer registered=").append(relayEnded);
        return b.append("\nactive tuples=").append(ledger.entries.size()).append(" unknown UID drops=").append(unknown).append(" unknown TCP=").append(unknownTcp).append(" unknown UDP=").append(unknownUdp).append(" unknown fixed DNS=").append(unknownDns).append(" policy drops=").append(policyDrop).append(" unsupported drops=").append(unsupported).append(" foreign reply drops=").append(foreignReply).append(" queue drops=").append(queueDrop).toString();
    }
    private void report(String s){
        Log.i(TAG,s);getSharedPreferences(PREFS,MODE_PRIVATE).edit().putString("status",s).apply();
        String state=s.startsWith("ACTIVE")?"ACTIVE":s.startsWith("BLOCKED")?"BLOCKED":s.startsWith("RECOVERING")?"RECOVERING":s.startsWith("CAPTURE LOST")?"CAPTURE_LOST":s.startsWith("STOPPED")?"STOPPED":s.startsWith("NOT STARTED")?"FAILED":"STARTING";
        publishMetrics(state);
    }
    private void publishMetrics(String state){
        long now=SystemClock.elapsedRealtime(),out=0,in=0;
        for(int i=0;i<count;i++){out+=outBytes[i];in+=inBytes[i];}
        if(state.equals("ACTIVE")&&lastSample>0){upRate=NativeRoutingMetrics.perSecond(lastOut,out,now-lastSample);downRate=NativeRoutingMetrics.perSecond(lastIn,in,now-lastSample);}else{upRate=0;downRate=0;}
        lastSample=now;lastOut=out;lastIn=in;
        long blocked=priorBlocked+(dnsRelay==null?0:dnsRelay.blocked.get());
        getSharedPreferences(PREFS,MODE_PRIVATE).edit().putString("state",state).putLong("heartbeat",now).putLong("upRate",upRate).putLong("downRate",downRate).putLong("blocked",blocked)
            .putString("dnsHealth",dnsRelay!=null&&state.equals("ACTIVE")?dnsRelay.health():"Not active").putString("dnsProbe",dnsRelay!=null&&state.equals("ACTIVE")?dnsRelay.probeStatus():"Not active").putString("dnsFunctional",dnsRelay!=null&&state.equals("ACTIVE")?dnsRelay.functionalStatus():"Not active").putString("dnsActiveConfig",dnsRelay!=null&&state.equals("ACTIVE")?NativeProtectedDnsRelay.NAMES[dnsProvider]+" · "+NativeDnsTransportPolicy.LABELS[dnsMode]+" · "+NativePeerProfiles.SLOTS[dnsRole]+" · "+dnsRelay.endpoint:"None")
            .putInt("dnsActiveProvider",dnsProvider).putInt("dnsActiveMode",dnsMode).putInt("dnsActiveRole",dnsRole).putInt("dnsActiveAlternate",dnsAlternate)
            .putString("underlay",physicalLabel(underlay)).putString("networkPreference",NativeUnderlayPolicy.LABELS[networkPreference])
            .putInt("isolationRole",isolationRole).putLong("networkMigrations",networkMigrations).putLong("lastRecoveryMs",lastRecoveryMs).putString("lastRecoveryReason",lastRecoveryReason).apply();
        notificationLine=state.equals("ACTIVE")?"↓ "+NativeRoutingMetrics.rate(downRate)+"  ↑ "+NativeRoutingMetrics.rate(upRate)+"  ·  blocked "+blocked:state.equals("BLOCKED")?"Traffic blocked · Stop to release":state.equals("RECOVERING")?"Recovering · traffic held":state.equals("CAPTURE_LOST")?"VPN capture lost · protection unconfirmed":state.equals("STARTING")?"Connecting · selected apps not yet protected":state;
        if(state.equals("ACTIVE")||state.equals("BLOCKED")||state.equals("RECOVERING")||state.equals("CAPTURE_LOST")||state.equals("STARTING")){
            NotificationManager manager=getSystemService(NotificationManager.class);
            if(manager!=null)try{manager.notify(8402,notification());}catch(SecurityException ignored){}
        }
    }
    private Notification notification(){
        NotificationManager m=getSystemService(NotificationManager.class);
        if(m!=null)m.createNotificationChannel(new NotificationChannel(TAG,"Selected app routing",NotificationManager.IMPORTANCE_LOW));
        PendingIntent open=PendingIntent.getActivity(this,8402,new Intent(this,NativeAppRoutingActivity.class),PendingIntent.FLAG_IMMUTABLE|PendingIntent.FLAG_UPDATE_CURRENT);
        PendingIntent stop=PendingIntent.getService(this,8403,new Intent(this,NativeAppRoutingService.class).setAction(STOP),PendingIntent.FLAG_IMMUTABLE|PendingIntent.FLAG_UPDATE_CURRENT);
        return new Notification.Builder(this,TAG).setSmallIcon(R.drawable.ic_vpn_status).setContentTitle("Wonhee Proxy · routing preview").setContentText(notificationLine).setStyle(new Notification.BigTextStyle().bigText(notificationLine)).setOnlyAlertOnce(true).setContentIntent(open).addAction(new Notification.Action.Builder(null,"Stop",stop).build()).setOngoing(true).build();
    }
}
