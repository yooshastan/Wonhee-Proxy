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
    private Network recoveryFrom,recoveryRequested;
    private String trialStatus="No recovery trial";
    private final long[] peerAge={-1,-1,-1},peerRx=new long[3],peerTx=new long[3];
    private boolean startupProbePending;
    private String lastVerifiedUnderlay="none";
    private long recoveryAttempts,recoverySuccess,recoveryDiscard,priorBlocked;
    private int dnsGeneration;
    private String retiredDnsStats="";
    private String[] sessionConfigs,sessionAddresses;
    private String sessionHomeCidr="";
    private static final int MAX_RECOVERY_ATTEMPTS=5;
    private static volatile boolean serviceRunning;
    static boolean running(){return serviceRunning;}
    // Local, process-memory-only diagnostic. Never include names, remote
    // addresses, or per-UID activity in exported logs or persistent preferences.
    private static volatile Map<Integer,String> uidEvidence=Collections.emptyMap();
    private static volatile long uidEvidenceAt;
    static String inspectUid(int uid){
        long age=SystemClock.elapsedRealtime()-uidEvidenceAt;
        if(!serviceRunning||uidEvidenceAt==0||age<0||age>8000)return "No fresh active observation";
        String evidence=uidEvidence.get(uid);
        return evidence==null?"No current admitted tuples observed for this UID":evidence;
    }
    private void publishUidEvidence(String state,long now){
        if(!"ACTIVE".equals(state)){uidEvidenceAt=0;uidEvidence=Collections.emptyMap();return;}
        Map<Integer,int[]> counts=new HashMap<>();
        for(NativeAppRoutingPolicy.Owner o:ledger.entries.values())
            if(o.uid>=10000&&o.role>=0&&o.role<3&&o.expiry>now)counts.computeIfAbsent(o.uid,k->new int[5])[o.role]++;
        for(NativeAppRoutingPolicy.Owner o:dnsLedger.entries.values())
            if(o.uid>=10000&&o.role>=0&&o.role<2&&o.expiry>now)counts.computeIfAbsent(o.uid,k->new int[5])[3+o.role]++;
        Map<Integer,String> result=new HashMap<>();
        for(Map.Entry<Integer,int[]> e:counts.entrySet()){
            int[] c=e.getValue();
            result.put(e.getKey(),"Admitted unexpired tuples — Exit A: "+c[0]+" · Exit B: "+c[1]+" · Home: "+c[2]
                +"\nManaged DNS tuples — Exit A: "+c[3]+" · Exit B: "+c[4]);
        }
        uidEvidence=Collections.unmodifiableMap(result);uidEvidenceAt=now;
    }
    private long lastSample,lastOut,lastIn,upRate,downRate;
    private long deniedRoute,deniedLedger,deniedNative,relayEnded;
    private String notificationLine="Connecting…";
    // Each exit owns its own TCP DNS state, socket pools, cache and pending queries.
    private final NativeProtectedDnsRelay[] dnsRelays=new NativeProtectedDnsRelay[2];
    private final NativeAppRoutingPolicy.Ledger dnsLedger=new NativeAppRoutingPolicy.Ledger();
    private int dnsStrategy=NativeAppRoutingPolicy.DNS_GLOBAL;
    private static final int FUNCTIONAL_A=-4,FUNCTIONAL_B=-5;
    private long dnsUnattributed,dnsUnattributedDropped,dnsIsolationDropped,dnsReplyRejected;
    private long activeBlocked(){long n=0;for(NativeProtectedDnsRelay r:dnsRelays)if(r!=null)n+=r.blocked.get();return n;}
    private NativeProtectedDnsRelay relayForSocket(NativeAppRoutingPolicy.Key key){
        if(key==null)return null;
        NativeProtectedDnsRelay found=null;
        for(NativeProtectedDnsRelay r:dnsRelays)if(r!=null&&r.owns(key)){
            if(found!=null)return null;found=r;
        }
        return found;
    }
    private int functionalOwner(NativeAppRoutingPolicy.Key key){
        int found=-1;
        for(NativeProtectedDnsRelay r:dnsRelays)if(r!=null&&r.functionalOwns(key)){
            if(found!=-1)return -1;found=r.role==0?FUNCTIONAL_A:FUNCTIONAL_B;
        }
        return found;
    }
    private String dnsStatus(int which){
        StringBuilder b=new StringBuilder();
        for(NativeProtectedDnsRelay r:dnsRelays)if(r!=null){
            if(b.length()>0)b.append(" · ");
            b.append(NativePeerProfiles.SLOTS[r.role]).append(": ").append(which==0?r.health():which==1?r.probeStatus():r.functionalStatus());
        }
        return b.length()==0?"Not active":b.toString();
    }
    private String dnsRouteLabel(){return dnsStrategy==NativeAppRoutingPolicy.DNS_GLOBAL?"Global "+NativePeerProfiles.SLOTS[dnsRole]:dnsStrategy==NativeAppRoutingPolicy.DNS_STRICT?"Follow DNS route · unattributed blocked":"Follow DNS route · unattributed via "+NativePeerProfiles.SLOTS[dnsRole];}
    private void runDnsTests(boolean functional,long now){
        for(NativeProtectedDnsRelay r:dnsRelays)if(r!=null&&!NativeRoutingSafety.held(r.role,isolationRole,now,isolationUntil)){
            if(functional)r.testFunctional();else r.testProvider();
        }
    }
    private long dnsFirewallDrops,ipv6Drops,otherUnsupported,unsupportedIpv4TcpUdp,unsupportedIpv4Other,unsupportedVersion,unknownTcp,unknownUdp,unknownDns;
    private boolean blockExternal853,allApps;
    private final Map<String,NativeAppRoutingPolicy.App> packageRules=new HashMap<>();
    private final long[][] portFlows=new long[NativeAppRoutingPolicy.SELECTORS.length][3];
    private int dnsProvider,dnsRole,dnsMode,dnsAlternate;
    private Set<String> blocklist=Collections.emptySet();
    private final AtomicBoolean started=new AtomicBoolean();
    private volatile boolean stopping,explicitStop;
    private NativeEgressGuard egressGuard;
    private NativeValidationDnsBridge validationBridge;
    private boolean validationWifi;
    private String validationStatus(){return validationBridge==null?"Off":validationBridge.status();}
    private String egressStatus(){return egressGuard==null?NativeEgressGuard.staleStatus(this):egressGuard.status();}
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
        if(STOP.equals(action)){explicitStop=true;requestStop();if(!started.get())stopSelf();return START_NOT_STICKY;}
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
    private final Map<Long,Long> underlayCooldown=new HashMap<>();
    private String peerEvidence="Not verified";
    private long validationLosses,nextValidationProbe;
    private boolean validationProbePending;
    private boolean lastAndroidValidated=true;
    private boolean guardedSession(){return egressGuard!=null&&!egressGuard.failed();}
    private boolean eligibleLink(Network n){
        NetworkCapabilities c=n==null?null:cm().getNetworkCapabilities(n);
        if(!physical(n)||c==null||!c.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            ||!c.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            ||!c.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
            ||!c.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_SUSPENDED)
            ||c.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL))return false;
        LinkProperties lp=cm().getLinkProperties(n);
        return lp!=null&&lp.getInterfaceName()!=null&&!lp.getInterfaceName().isEmpty();
    }
    private boolean sessionUsable(Network n){
        return NativeUnderlayPolicy.sessionCandidate(eligibleLink(n),usable(n),guardedSession());
    }
    private boolean usable(Network n){
        NetworkCapabilities c=n==null?null:cm().getNetworkCapabilities(n);
        return eligibleLink(n)&&c!=null&&c.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            &&c.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            &&c.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            &&c.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
            &&c.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_SUSPENDED);
    }
    private static long id(Network n){return n==null?0:n.getNetworkHandle();}
    private Network preferredNetwork(){return pickNetwork(false,false);}
    private Network pickNetwork(boolean allowUnvalidated,boolean honorCooldown){
        long now=SystemClock.elapsedRealtime();
        underlayCooldown.entrySet().removeIf(e->e.getValue()<=now);
        Map<Long,Integer> candidates=new HashMap<>();
        Map<Long,Network> networks=new HashMap<>();
        for(Network n:cm().getAllNetworks())if(usable(n)||(allowUnvalidated&&sessionUsable(n))){
            NetworkCapabilities c=cm().getNetworkCapabilities(n);if(c==null)continue;
            long key=id(n);
            if(honorCooldown&&!NativeUnderlayPolicy.trialAllowed(now,underlayCooldown.getOrDefault(key,0L)))continue;
            candidates.put(key,c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)?NativeUnderlayPolicy.WIFI:NativeUnderlayPolicy.CELL);
            networks.put(key,n);
        }
        Network best=systemBest;
        if(best==null){Network active=cm().getActiveNetwork();if(usable(active))best=active;}
        return networks.get(NativeUnderlayPolicy.pick(networkPreference,id(underlay),id(best),candidates));
    }
    private Network migrationCandidate(){
        if(!guardedSession())return preferredNetwork();
        // Do not follow Android's best-network score off a still-working link
        // merely because the direct validation probes are blocked.
        if(NativeUnderlayPolicy.retainUnvalidated(networkPreference,true,eligibleLink(underlay),usable(underlay),true))return underlay;
        // Explicit Wi-Fi/cellular preferences may trial an attached but
        // unvalidated candidate. A failed authenticated trial is cooled down.
        if(networkPreference==NativeUnderlayPolicy.WIFI_FIRST||networkPreference==NativeUnderlayPolicy.CELL_FIRST)
            return pickNetwork(true,true);
        Network candidate=pickNetwork(false,true);
        return candidate==null?underlay:candidate;
    }
    private Network recoveryCandidate(int attempt){
        if(!guardedSession())return preferredNetwork();
        long now=SystemClock.elapsedRealtime();
        Map<Long,Integer> eligible=new HashMap<>();
        Map<Long,Network> candidates=new HashMap<>();
        for(Network n:cm().getAllNetworks())if(sessionUsable(n)&&NativeUnderlayPolicy.trialAllowed(now,underlayCooldown.getOrDefault(id(n),0L))){
            candidates.put(id(n),n);eligible.put(id(n),1);
        }
        long target=NativeUnderlayPolicy.recoveryTarget(attempt,id(recoveryRequested),id(recoveryFrom),eligible);
        if(target!=0)return candidates.get(target);
        Network candidate=pickNetwork(true,true);
        // When every eligible link is cooled down, bounded recovery may
        // retry an eligible link rather than strand a single-network device.
        // No forwarding until all fresh protected peers are verified.
        return candidate!=null?candidate:pickNetwork(true,false);
    }
    private String peerDetails(long now){
        StringBuilder b=new StringBuilder();
        for(int i=0;i<count;i++){
            if(i>0)b.append("\n");
            b.append(NativePeerProfiles.SLOTS[i]).append(" · ");
            if(NativeRoutingSafety.held(i,isolationRole,now,isolationUntil))b.append("traffic held · ");
            b.append(peerAge[i]<0?"handshake unverified":"handshake age "+peerAge[i]+" s");
            b.append(" · peer RX/TX ").append(peerRx[i]).append("/").append(peerTx[i]).append(" bytes");
        }
        return b.length()==0?"Not verified":b.toString();
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
        return type+" #"+n.toString()+" ("+(usable(n)?"Android validated":eligibleLink(n)?"Android not validated · link eligible":"link unavailable/restricted")+")";
    }
    private String underlaySummary(){
        return "underlay="+physicalLabel(underlay)+" preference="+NativeUnderlayPolicy.LABELS[networkPreference]
            +" network migrations="+networkMigrations+" last recovery reason="+lastRecoveryReason+" last recovery ms="+lastRecoveryMs
            +" physical callback="+callbacksRegistered+" system best callback="+bestRegistered
            +" last verified underlay="+lastVerifiedUnderlay
            +" Android validation losses="+validationLosses+" peer evidence="+peerEvidence
            +" candidate cooldowns="+underlayCooldown.size()+" trial="+trialStatus;
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
        if(validationBridge!=null)validationBridge.setRelay(null);
        StringBuilder stats=new StringBuilder();
        for(NativeProtectedDnsRelay old:dnsRelays)if(old!=null)old.close();
        for(int i=0;i<dnsRelays.length;i++){
            NativeProtectedDnsRelay old=dnsRelays[i];if(old==null)continue;
            if(!old.awaitStopped())cleanupFailed=true;
            priorBlocked+=old.blocked.get();
            if(stats.length()>0)stats.append("\n");
            stats.append("last DNS generation=").append(dnsGeneration).append(" role=").append(NativePeerProfiles.SLOTS[i]).append(" queries=").append(old.queries.get()).append(" authenticated=").append(old.verified.get()).append(" blocked=").append(old.blocked.get()).append(" failed=").append(old.failed.get()).append(" overflow=").append(old.overflow.get());
            dnsRelays[i]=null;
        }
        if(stats.length()>0)retiredDnsStats=stats.toString();
        dnsLedger.entries.clear();
    }
    private void newRelay()throws Exception{
        Network vpn=vpnNetwork();if(vpn==null)throw new IllegalStateException();
        for(int role=0;role<2;role++)if(dnsStrategy!=NativeAppRoutingPolicy.DNS_GLOBAL||role==dnsRole)
            dnsRelays[role]=new NativeProtectedDnsRelay(vpn,dnsProvider,role,dnsMode,dnsAlternate,blocklist);
        dnsGeneration++;startupProbePending=true;
    }
    private void createPeers()throws Exception{
        peerEvidence="Awaiting fresh protected peer handshakes";
        Arrays.fill(peerAge,-1);Arrays.fill(peerRx,0);Arrays.fill(peerTx,0);
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
        if(!autoRecovery||guardTest||cleanupFailed||!captureIntact()||(egressGuard!=null&&egressGuard.failed()))return false;
        for(int attempt=0;attempt<MAX_RECOVERY_ATTEMPTS&&!stopping&&!guardTest;attempt++){
            long wait=NativeRecoveryPlan.delay(attempt),until=SystemClock.elapsedRealtime()+wait;
            report(stats("RECOVERING — selected apps held in existing TUN; retry "+(attempt+1)+"/"+MAX_RECOVERY_ATTEMPTS));
            while(SystemClock.elapsedRealtime()<until&&!stopping&&!guardTest){
                if(!captureIntact()||(egressGuard!=null&&egressGuard.failed()))return false;discardCaptured();Thread.sleep(50);
            }
            if(stopping||guardTest||!captureIntact()||!dnsOff()||(egressGuard!=null&&egressGuard.failed()))return false;
            recoveryAttempts++;
            Network next=recoveryCandidate(attempt);
            if(next==null)continue;
            underlay=next;
            boolean speculative=guardedSession()&&recoveryFrom!=null&&!next.equals(recoveryFrom);
            long budget=NativeUnderlayPolicy.handshakeBudget(speculative);
            trialStatus="Testing "+physicalLabel(next)+"; budget "+budget+" ms";
            Log.i(TAG,"UNDERLAY TRIAL — "+trialStatus+"; forwarding held until fresh peer handshakes");
            try{
                if(!setUnderlyingNetworks(new Network[]{next}))throw new IllegalStateException();
                createPeers();
                long deadline=SystemClock.elapsedRealtime()+budget;
                while(!stopping&&!guardTest){
                    if(!captureIntact()||!dnsOff()||!sessionUsable(next)||!protectedSockets()||(egressGuard!=null&&egressGuard.failed()))throw new IllegalStateException();
                    discardCaptured();
                    if(ready())break;
                    if(SystemClock.elapsedRealtime()>=deadline)throw new IllegalStateException();
                    Thread.sleep(100);
                }
                if(stopping||guardTest||!captureIntact()||!dnsOff()||!sessionUsable(next)||!ready()||(egressGuard!=null&&egressGuard.failed()))throw new IllegalStateException();
                discardCaptured();
                ledger.entries.clear();
                newRelay();
                recoverySuccess++;
                if(recoveryFrom!=null&&!recoveryFrom.equals(next))networkMigrations++;
                lastRecoveryMs=SystemClock.elapsedRealtime()-recoveryStarted;
                lastVerifiedUnderlay=physicalLabel(next);lastAndroidValidated=usable(next);migration.reset();
                validationProbePending=guardedSession()&&!lastAndroidValidated;
                underlayCooldown.remove(id(next));
                trialStatus="Verified "+physicalLabel(next);
                if(isolationRole>=0&&SystemClock.elapsedRealtime()<isolationUntil)
                    Log.i(TAG,"ISOLATION TEST — retained "+NativePeerProfiles.SLOTS[isolationRole]+" through recovery; original deadline unchanged");
                report(stats("ACTIVE — recovery verified; same TUN retained; "+lastRecoveryReason+"; "+lastRecoveryMs+" ms"));
                return true;
            }catch(Exception|LinkageError failure){
                retireDns();if(!closePeers())cleanupFailed=true;
                if(guardedSession()){
                    underlayCooldown.put(id(next),SystemClock.elapsedRealtime()+NativeUnderlayPolicy.FAILED_TRIAL_COOLDOWN_MS);
                    trialStatus="Failed "+physicalLabel(next)+"; candidate cooled down";
                    Log.i(TAG,"UNDERLAY TRIAL — not verified; candidate cooled down for 120 seconds");
                }
                if(cleanupFailed||(egressGuard!=null&&egressGuard.failed()))return false;
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
            if(NativeEgressGuard.pending(this))throw new NativePeerProfiles.Rejected("EGRESS_JOURNAL_PENDING_RECOVER_OFFLINE");
            boolean rootGuard=intent.getBooleanExtra("rootEgressGuard",false);
            boolean validationCompat=intent.getBooleanExtra("validationCompat",false);
            if(validationCompat&&(!rootGuard||intent.getIntExtra("dnsStrategy",0)!=NativeAppRoutingPolicy.DNS_STRICT))throw new NativePeerProfiles.Rejected("VALIDATION_REQUIRES_ROOT_GUARD_AND_STRICT_DNS");
            if(rootGuard&&!intent.getBooleanExtra("allApps",false))throw new NativePeerProfiles.Rejected("EGRESS_REQUIRES_ALL_APP_CAPTURE");
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
            dnsStrategy=intent.getIntExtra("dnsStrategy",0);
            dnsProvider=intent.getIntExtra("dnsProvider",0);dnsRole=intent.getIntExtra("dnsRole",0);dnsMode=intent.getIntExtra("dnsMode",0);dnsAlternate=intent.getIntExtra("dnsAlternate",0);
            if(dnsStrategy<0||dnsStrategy>2||!NativeDnsTransportPolicy.supports(dnsProvider,dnsMode)||dnsRole<0||dnsRole>1||dnsAlternate<0||dnsAlternate>1)throw new IllegalArgumentException();
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
                if(!dnsOff())throw new NativePeerProfiles.Rejected("PRIVATE_DNS_CHANGED");
                if(!usable(underlay))throw new NativePeerProfiles.Rejected("UNDERLAY_NOT_VALIDATED");
                if(!noVpn())throw new NativePeerProfiles.Rejected("OTHER_VPN_PRESENT");
                if(!protectedSockets())throw new NativePeerProfiles.Rejected("PEER_SOCKET_PROTECTION_FAILED");
                if(ready())break;
                if(SystemClock.elapsedRealtime()>=deadline)throw new NativePeerProfiles.Rejected("PEER_HANDSHAKE_TIMEOUT");
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
            if(rootGuard){
                stage="root-egress-guard";
                Network vpn=vpnNetwork();LinkProperties link=vpn==null?null:cm().getLinkProperties(vpn);
                if(link==null)throw new NativePeerProfiles.Rejected("EGRESS_TUN_NOT_IDENTIFIED");
                if(validationCompat)validationBridge=new NativeValidationDnsBridge();
                egressGuard=new NativeEgressGuard(this);
                egressGuard.install(link.getInterfaceName(),sessionConfigs,intent.getBooleanExtra("rootLocalDiscovery",false),validationBridge==null?0:validationBridge.port());
                if(stopping)return;
            }
            stage="dns-relay";
            newRelay();
            lastVerifiedUnderlay=physicalLabel(underlay);lastAndroidValidated=usable(underlay);
            validationProbePending=guardedSession()&&!lastAndroidValidated;
            stage="forwarding";report("ACTIVE — "+count+" verified peers; "+(allApps?"all-app preview":apps.length+" selected apps")+"; configured "+NativeDnsTransportPolicy.LABELS[dnsMode]+" · "+dnsRouteLabel()+"; hosts="+blocklist.size()+"; IPv6 blocked");
            long nextReport=0,nextHealth=0;
            while(!stopping){
                long now=SystemClock.elapsedRealtime();
                if(egressGuard!=null&&egressGuard.failed()){stage="root-egress-verification";throw new IllegalStateException();}
                String reason=null;Network requestedMigration=null;
                if(now>=nextHealth||networkDirty.getAndSet(false)){
                    if(!dnsOff()){stage="private-dns-changed";throw new IllegalStateException();}
                    if(!captureIntact()){stage="vpn-capture-lost";throw new IllegalStateException();}
                    LinkProperties physicalLink=cm().getLinkProperties(underlay);
                    validationWifi=physicalLink!=null&&"wlan0".equals(physicalLink.getInterfaceName());
                    boolean androidValidated=usable(underlay);
                    boolean peerReady=protectedSockets()&&ready();
                    if(androidValidated!=lastAndroidValidated){
                        if(!androidValidated){validationLosses++;validationProbePending=guardedSession();}
                        Log.i(TAG,"UNDERLAY VALIDATION — "+(androidValidated?"Android validated":"Android validation lost")
                            +"; link eligible="+eligibleLink(underlay)+"; recent peer proof="+peerReady);
                        lastAndroidValidated=androidValidated;
                    }
                    if(!sessionUsable(underlay))reason="physical-underlay-lost";
                    else if(!peerReady)reason="peer-health";
                    else if(autoRecovery){
                        Network candidate=migrationCandidate();
                        if(migration.due(id(underlay),id(candidate),now)){reason="preferred-network-migration";requestedMigration=candidate;}
                    }
                    nextHealth=now+1000;
                }
                if(guardTest){stage="controlled-guard-test";throw new IllegalStateException();}
                int request=isolationRequest.getAndSet(-2);
                if(request==-1||(isolationRole>=0&&now>=isolationUntil)){
                    isolationRole=-1;isolationUntil=0;Log.i(TAG,"ISOLATION TEST — ended; normal assigned routes restored");
                }
                if(request>=0){
                    if(NativeRoutingSafety.isolationAllowed(request,count,dnsRole,dnsStrategy!=NativeAppRoutingPolicy.DNS_GLOBAL)){
                        isolationRole=request;isolationUntil=now+NativeRoutingSafety.ISOLATION_MS;
                        Log.i(TAG,"ISOLATION TEST — holding "+NativePeerProfiles.SLOTS[request]+" for 90 seconds; no reroute");
                    }else Log.i(TAG,"ISOLATION TEST — refused: inactive slot or configured DNS exit");
                }
                if(recoveryTest||reason!=null){
                    stage=recoveryTest?"controlled-recovery-test":reason;recoveryTest=false;
                    // Recovery does not cancel an isolation test. The original
                    // elapsedRealtime deadline remains authoritative in pump().
                    lastRecoveryReason=stage;recoveryStarted=SystemClock.elapsedRealtime();recoveryFrom=underlay;
                    recoveryRequested=stage.equals("preferred-network-migration")?requestedMigration:recoveryFrom;
                    migration.reset();
                    report(stats("RECOVERING — "+stage+"; stopping forwarding"));
                    retireDns();if(!closePeers())cleanupFailed=true;ledger.entries.clear();
                    if(!recover())throw new IllegalStateException("recovery unavailable");
                    stage="forwarding";nextHealth=0;nextReport=0;continue;
                }
                // Diagnostic only: a resolver outage must not be mistaken for
                // physical link loss. Probe fixed example.com inside active
                // encrypted relays only, never a held exit or direct underlay.
                if(guardedSession()&&!lastAndroidValidated&&(validationProbePending||now>=nextValidationProbe)){
                    validationProbePending=false;nextValidationProbe=now+30000;
                    Log.i(TAG,"UNDERLAY PROBE — encrypted DNS through non-held exits; diagnostic only");
                    runDnsTests(false,now);
                }
                if(dnsTest.getAndSet(false))runDnsTests(false,now);
                if(functionalTest.getAndSet(false))runDnsTests(true,now);
                if(validationBridge!=null)validationBridge.setRelay(validationWifi&&!NativeRoutingSafety.held(0,isolationRole,now,isolationUntil)?dnsRelays[0]:null);
                pump(now);
                // Prime configured encrypted relays after the pump is running;
                // skip any held role and never use the physical resolver.
                if(startupProbePending){startupProbePending=false;runDnsTests(false,now);}
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
            boolean ok=closePeers()&&!cleanupFailed;
            // Stop is explicit. Unexpected revocation/destruction retains the narrow
            // owned firewall record for deliberate offline recovery.
            if(egressGuard!=null){
                Thread.interrupted();
                if(explicitStop){if(!egressGuard.remove())ok=false;}
                else{egressGuard.retain();ok=false;}
            }
            if(validationBridge!=null)validationBridge.close();
            if(tun!=null){try{tun.close();}catch(Exception e){ok=false;}tun=null;}
            if(stopping||captured)report(stats(ok?"STOPPED — peer sessions released; TUN closed; normal networking resumes":"STOPPED — cleanup unconfirmed"));
            serviceRunning=false;
            stopForeground(STOP_FOREGROUND_REMOVE);stopSelf();
        }
    }
    private boolean protectedSockets(){long[] p=RootlessNativeBridge.protectionStats();return p!=null&&p.length>=2&&p[0]==2L*count&&p[1]==0;}
    private boolean ready(){
        long maxAge=0,now=System.currentTimeMillis()/1000L;
        String missing=null;
        for(int i=0;i<count;i++){
            long[] s=RootlessNativeBridge.peerStats(handles[i]);
            if(s==null||s.length<3||s[0]<=0||s[1]<=0||s[2]<=0||now-s[0]>240||now-s[0]<-5){
                peerAge[i]=-1;peerRx[i]=0;peerTx[i]=0;
                if(missing==null)missing=NativePeerProfiles.SLOTS[i];continue;
            }
            peerAge[i]=Math.max(0,now-s[0]);peerRx[i]=s[1];peerTx[i]=s[2];
            maxAge=Math.max(maxAge,peerAge[i]);
        }
        peerEvidence=missing==null?count+" peers · oldest handshake "+maxAge+" s":missing+" lacks recent authenticated handshake evidence";
        return missing==null;
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
            if(uid==android.os.Process.myUid()){
                int functional=functionalOwner(key);if(functional!=-1)return functional;
                return relayForSocket(key)!=null?RELAY_UID:-1;
            }
            // Android's shared system resolver is not proof of originating app.
            if(dnsStrategy!=NativeAppRoutingPolicy.DNS_GLOBAL&&key.fixedDns()&&uid<10000)return UNKNOWN_DNS;
            if(resolveOwner(uid))return uid;
            // Android resolver may own the DNS socket rather than selected app.
            // Only the fixed in-tunnel DNS server has a resolver exception.
            if(key.fixedDns()&&(uid<0||uid<10000))return UNKNOWN_DNS;
        }catch(Exception ignored){}
        return -1;
    }
    private void pump(long now)throws Exception{
        ledger.sweep(now);dnsLedger.sweep(now);
        for(int k=0;k<64;k++){
            int n;try{n=Os.read(tun.getFileDescriptor(),buffer,0,buffer.length);}catch(ErrnoException e){if(e.errno==OsConstants.EAGAIN)break;throw e;}
            if(n<=0)throw new IllegalStateException();
            byte[] p=Arrays.copyOf(buffer,n);
            NativeAppRoutingPolicy.Key key=NativeAppRoutingPolicy.key(p,false);
            if(key==null){unsupported++;if((p[0]&0xf0)==0x60)ipv6Drops++;else{otherUnsupported++;if((p[0]&0xf0)==0x40&&p.length>=20){int proto=p[9]&255;if(proto==6||proto==17)unsupportedIpv4TcpUdp++;else unsupportedIpv4Other++;}else unsupportedVersion++;}continue;}
            NativeAppRoutingPolicy.Owner prior=(key.fixedDns()?dnsLedger:ledger).get(key,now);
            boolean syn=NativeAppRoutingPolicy.syn(p);
            int owner=prior!=null&&key.proto==6&&!syn?prior.uid:uid(key);
            if(owner==-1){unknown++;if(key.proto==6)unknownTcp++;else if(key.proto==17)unknownUdp++;if(key.fixedDns())unknownDns++;continue;}
            if(key.remotePort==53){
                if(!key.fixedDns()){dnsFirewallDrops++;continue;}
                if(owner==UNKNOWN_DNS)dnsUnattributed++;
                int route=owner==FUNCTIONAL_A?0:owner==FUNCTIONAL_B?1:policy.dnsExit(key,owners.get(owner),owner==UNKNOWN_DNS,dnsStrategy,dnsRole);
                if(route<0||route>1||dnsRelays[route]==null){
                    if(owner==UNKNOWN_DNS)dnsUnattributedDropped++;
                    dnsFirewallDrops++;continue;
                }
                if(NativeRoutingSafety.held(route,isolationRole,now,isolationUntil)){dnsIsolationDropped++;continue;}
                if(dnsLedger.admit(key,syn,owner,route,now)==null){dnsReplyRejected++;continue;}
                NativeProtectedDnsRelay dnsRelay=dnsRelays[route];
                if(key.proto==17){dnsRelay.submit(p);continue;}
                if(key.proto==6&&dnsRelay.feedTcp(p))continue;
                dnsFirewallDrops++;continue;
            }
            if(owner!=RELAY_UID&&key.remotePort==853&&blockExternal853){dnsFirewallDrops++;continue;}
            NativeProtectedDnsRelay dnsRelay=owner==RELAY_UID?relayForSocket(key):null;
            int role=owner==RELAY_UID?(dnsRelay==null?-1:dnsRelay.role):policy.choose(key,owners.get(owner),false);
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
        for(NativeProtectedDnsRelay dnsRelay:dnsRelays)if(dnsRelay!=null){
            boolean held=NativeRoutingSafety.held(dnsRelay.role,isolationRole,now,isolationUntil);
            if(!held)dnsRelay.drainTcpQueries();
            for(int k=0;k<64;k++){
            byte[] response=dnsRelay.poll();if(response==null)break;
            if(held){dnsIsolationDropped++;continue;}
            NativeAppRoutingPolicy.Key reply=NativeAppRoutingPolicy.key(response,true);
            if(reply==null||!reply.fixedDns()||!dnsLedger.reply(reply,dnsRelay.role,now)){dnsReplyRejected++;continue;}
            try{if(Os.write(tun.getFileDescriptor(),response,0,response.length)!=response.length)throw new IllegalStateException();}
            catch(ErrnoException e){if(e.errno==OsConstants.EAGAIN){queueDrop++;continue;}throw e;}
            }
        }
        for(int i=0;i<count;i++)for(int k=0;k<64;k++){
            int n=RootlessNativeBridge.pollRoutePacket(handles[i],buffer);
            if(n==0)break;if(n==-4){foreignReply++;continue;}if(n<0)throw new IllegalStateException();
            if(NativeRoutingSafety.held(i,isolationRole,now,isolationUntil)){isolationIn[i]++;continue;}
            byte[] p=rewrite[i].toTun(Arrays.copyOf(buffer,n));
            NativeAppRoutingPolicy.Key key=NativeAppRoutingPolicy.key(p,true);
            NativeProtectedDnsRelay dnsRelay=relayForSocket(key);
            if(key==null||!ledger.reply(key,i,now)){if(dnsRelay!=null&&dnsRelay.quicOwns(key))dnsRelay.quicTunRejected.incrementAndGet();foreignReply++;continue;}
            try{if(Os.write(tun.getFileDescriptor(),p,0,p.length)!=p.length)throw new IllegalStateException();}
            catch(ErrnoException e){if(e.errno==OsConstants.EAGAIN){queueDrop++;continue;}throw e;}
            if(dnsRelay!=null&&dnsRelay.quicOwns(key)&&i==dnsRelay.role)dnsRelay.quicTunRx.incrementAndGet();
            incoming[i]++;inBytes[i]+=p.length;
        }
    }
    private boolean closePeers(){
        peerEvidence="Peer sessions closed";Arrays.fill(peerAge,-1);Arrays.fill(peerRx,0);Arrays.fill(peerTx,0);
        boolean ok=true;
        for(int i=handles.length-1;i>=0;i--)if(handles[i]>0){
            try{if(!RootlessNativeBridge.closeSession(handles[i]))ok=false;}catch(Exception|LinkageError e){ok=false;}handles[i]=0;
        }
        if(registered){try{if(!RootlessNativeBridge.clearVpnService(this))ok=false;}catch(Exception|LinkageError e){ok=false;}registered=false;}
        return ok;
    }
    private String stats(String prefix){
        StringBuilder b=new StringBuilder(prefix);
        b.append("\nRoot egress guard=").append(egressStatus());
        b.append("\nValidation DNS bridge=").append(validationStatus());
        b.append("\nIsolation test=").append(isolationRole>=0?NativePeerProfiles.SLOTS[isolationRole]:"off").append(" held out A/B/Home=").append(isolationOut[0]).append("/").append(isolationOut[1]).append("/").append(isolationOut[2]).append(" held in A/B/Home=").append(isolationIn[0]).append("/").append(isolationIn[1]).append("/").append(isolationIn[2]);
        for(int j=0;j<categoryFlows.length;j++)if(categoryFlows[j][0]+categoryFlows[j][1]+categoryFlows[j][2]>0)b.append("\nCategory flows ").append(AppUseCategories.LABELS[j]).append(" A/B/Home=").append(categoryFlows[j][0]).append("/").append(categoryFlows[j][1]).append("/").append(categoryFlows[j][2]);
        b.append("\nCapture mode=").append(allApps?"all-app preview":"selected apps").append(" resolved UIDs=").append(owners.size());
        for(int j=0;j<portFlows.length;j++)if(portFlows[j][0]+portFlows[j][1]+portFlows[j][2]>0)b.append("\nPort flows ").append(NativeAppRoutingPolicy.SELECTOR_NAMES[j]).append(" A/B/Home=").append(portFlows[j][0]).append("/").append(portFlows[j][1]).append("/").append(portFlows[j][2]);
        for(int i=0;i<count;i++)b.append("\n").append(NativePeerProfiles.SLOTS[i]).append(" new flows=").append(opened[i]).append(" packets out/in=").append(outgoing[i]).append('/').append(incoming[i]).append(" bytes out/in=").append(outBytes[i]).append('/').append(inBytes[i]);
        b.append("\nDNS strategy=").append(dnsRouteLabel()).append(" unattributed packets=").append(dnsUnattributed).append(" unattributed denied=").append(dnsUnattributedDropped).append(" isolation DNS drops=").append(dnsIsolationDropped).append(" DNS ownership rejections=").append(dnsReplyRejected);
        for(NativeProtectedDnsRelay dnsRelay:dnsRelays)if(dnsRelay!=null)b.append("\nDNS provider=").append(NativeProtectedDnsRelay.NAMES[dnsProvider]).append(" role=").append(NativePeerProfiles.SLOTS[dnsRelay.role]).append(" queries=").append(dnsRelay.queries.get()).append(" authenticated=").append(dnsRelay.verified.get()).append(" blocked=").append(dnsRelay.blocked.get()).append(" failed=").append(dnsRelay.failed.get()).append(" overflow=").append(dnsRelay.overflow.get()).append(" hosts=").append(blocklist.size()).append(" cache hits=").append(dnsRelay.cacheHits.get()).append(" cached entries=").append(dnsRelay.cacheSize()).append(" TLS opened=").append(dnsRelay.tlsConnections.get()).append(" TLS reused=").append(dnsRelay.tlsReuse.get()).append(" TLS fresh retries=").append(dnsRelay.tlsRetries.get()).append(" TLS closed=").append(dnsRelay.tlsClosed.get()).append(" retry EOF=").append(dnsRelay.retryEof.get()).append(" retry timeout=").append(dnsRelay.retryTimeout.get()).append(" retry TLS=").append(dnsRelay.retryTls.get()).append(" retry other=").append(dnsRelay.retryOther.get()).append(" active relay sockets=").append(dnsRelay.socketCount()).append(" registered relay ports=").append(dnsRelay.portCount()).append(" DNS transport=").append(NativeDnsTransportPolicy.LABELS[dnsMode]).append(" UDP queries=").append(dnsRelay.udpQueries.get()).append(" TCP queries=").append(dnsRelay.tcpQueries.get()).append(" TCP rejected=").append(dnsRelay.tcpRejected.get()).append(" UDP truncated=").append(dnsRelay.udpTruncated.get()).append(" QUIC cold trials=").append(dnsRelay.coldQuicTrials.get()).append(" QUIC opened=").append(dnsRelay.quicOpened.get()).append(" QUIC verified=").append(dnsRelay.quicVerified.get()).append(" QUIC failed=").append(dnsRelay.quicFailed.get()).append(" QUIC attempts=").append(dnsRelay.quicAttempts.get()).append(" QUIC reused=").append(dnsRelay.quicReused.get()).append(" QUIC closed=").append(dnsRelay.quicClosed.get()).append(" QUIC backoff=").append(dnsRelay.quicBackoff.get()).append(" QUIC timeout=").append(dnsRelay.quicTimeout.get()).append(" QUIC certificate=").append(dnsRelay.quicCertificate.get()).append(" QUIC socket error=").append(dnsRelay.quicSocketError.get()).append(" QUIC invalid=").append(dnsRelay.quicInvalid.get()).append(" QUIC other=").append(dnsRelay.quicOther.get()).append(" DNS coalesced=").append(dnsRelay.coalesced.get()).append(" DNS latency samples=").append(dnsRelay.dnsLatencySamples.get()).append(" DNS upstream total ms=").append(dnsRelay.dnsLatencyTotalMs.get()).append(" DNS upstream max ms=").append(dnsRelay.dnsLatencyMaxMs.get()).append(" endpoint=").append(dnsRelay.endpoint).append(" QUIC fresh retries=").append(dnsRelay.quicFreshRetries.get()).append(" QUIC retry success=").append(dnsRelay.quicRetrySuccess.get()).append(" QUIC fresh failures=").append(dnsRelay.quicFreshFailures.get()).append(" QUIC handshake timeout=").append(dnsRelay.quicHandshakeTimeout.get()).append(" endpoint port=").append(NativeDnsTransportPolicy.port(dnsMode)).append(" SNI=").append(NativeProtectedDnsRelay.HOSTS[dnsProvider]).append(" ALPN=").append(dnsMode==NativeDnsTransportPolicy.DOQ?"doq":dnsMode==NativeDnsTransportPolicy.DOH3?"h3":"n/a").append(" QUIC handshake retries=").append(dnsRelay.quicHandshakeRetries.get()).append(" QUIC handshake timeout last ms=").append(dnsRelay.quicHandshakeTimeoutLastMs.get()).append(" QUIC fresh exchange last ms=").append(dnsRelay.quicFreshExchangeLastMs.get()).append(" QUIC stream reset=").append(dnsRelay.quicStreamReset.get()).append(" QUIC remote close=").append(dnsRelay.quicRemoteClose.get()).append(" QUIC transport error=").append(dnsRelay.quicTransportError.get()).append(" QUIC TLS error=").append(dnsRelay.quicTlsError.get()).append(" QUIC socket tx=").append(dnsRelay.quicSocketTx.get()).append(" rx=").append(dnsRelay.quicSocketRx.get()).append(" tx min/max=").append(dnsRelay.quicTxMin.get()).append('/').append(dnsRelay.quicTxMax.get()).append(" rx min/max=").append(dnsRelay.quicRxMin.get()).append('/').append(dnsRelay.quicRxMax.get()).append(" write/read errors=").append(dnsRelay.quicWriteErrors.get()).append('/').append(dnsRelay.quicReadErrors.get()).append(" timeout tx/rx=").append(dnsRelay.lastTimeoutTx.get()).append('/').append(dnsRelay.lastTimeoutRx.get()).append(" QUIC TUN tx=").append(dnsRelay.quicTunTx.get()).append(" rx=").append(dnsRelay.quicTunRx.get()).append(" rejected=").append(dnsRelay.quicTunRejected.get()).append(" DNS probe attempts=").append(dnsRelay.probeAttempts.get()).append(" DNS probe passed=").append(dnsRelay.probePassed.get()).append(" DNS probe failed=").append(dnsRelay.probeFailed.get()).append(" DNS health=").append(dnsRelay.health()).append(" DNS probe=").append(dnsRelay.probeStatus()).append(" DNS functional test=").append(dnsRelay.functionalStatus());
        if(dnsRelays[0]==null&&dnsRelays[1]==null&&!retiredDnsStats.isEmpty())b.append("\n").append(retiredDnsStats);
        b.append("\n").append(underlaySummary());
        b.append("\nPeer transport evidence: ").append(peerDetails(SystemClock.elapsedRealtime()).replace("\n"," | "));
        b.append("\nrecovery attempts=").append(recoveryAttempts).append(" successes=").append(recoverySuccess).append(" discarded packets=").append(recoveryDiscard).append(" DNS generation=").append(dnsGeneration).append(" session blocked=").append(priorBlocked+activeBlocked());
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
        publishUidEvidence(state,now);
        for(int i=0;i<count;i++){out+=outBytes[i];in+=inBytes[i];}
        if(state.equals("ACTIVE")&&lastSample>0){upRate=NativeRoutingMetrics.perSecond(lastOut,out,now-lastSample);downRate=NativeRoutingMetrics.perSecond(lastIn,in,now-lastSample);}else{upRate=0;downRate=0;}
        lastSample=now;lastOut=out;lastIn=in;
        long blocked=priorBlocked+activeBlocked();
        getSharedPreferences(PREFS,MODE_PRIVATE).edit().putString("state",state).putLong("heartbeat",now).putLong("upRate",upRate).putLong("downRate",downRate).putLong("blocked",blocked)
            .putString("dnsHealth",state.equals("ACTIVE")?dnsStatus(0):"Not active").putString("dnsProbe",state.equals("ACTIVE")?dnsStatus(1):"Not active").putString("dnsFunctional",state.equals("ACTIVE")?dnsStatus(2):"Not active").putString("dnsActiveConfig",state.equals("ACTIVE")?NativeProtectedDnsRelay.NAMES[dnsProvider]+" · "+NativeDnsTransportPolicy.LABELS[dnsMode]+" · "+dnsRouteLabel():"None")
            .putInt("dnsActiveStrategy",dnsStrategy).putInt("dnsActiveProvider",dnsProvider).putInt("dnsActiveMode",dnsMode).putInt("dnsActiveRole",dnsRole).putInt("dnsActiveAlternate",dnsAlternate)
            .putString("egressGuardStatus",egressStatus()).putString("validationStatus",validationStatus()).putString("peerEvidence",peerEvidence).putString("peerDetails",state.equals("ACTIVE")?peerDetails(now):"Not active").putString("trialStatus",trialStatus).putLong("validationLosses",validationLosses).putString("underlay",physicalLabel(underlay)).putString("networkPreference",NativeUnderlayPolicy.LABELS[networkPreference])
            .putLong("isolationUntil",isolationUntil).putInt("isolationRole",isolationRole).putLong("networkMigrations",networkMigrations).putLong("lastRecoveryMs",lastRecoveryMs).putString("lastRecoveryReason",lastRecoveryReason).apply();
        notificationLine=state.equals("ACTIVE")?"↓ "+NativeRoutingMetrics.rate(downRate)+"  ↑ "+NativeRoutingMetrics.rate(upRate)+"  ·  blocked "+blocked:state.equals("BLOCKED")?"Traffic blocked · Stop to release":state.equals("RECOVERING")?"Recovering · traffic held":state.equals("CAPTURE_LOST")?"VPN capture lost · protection unconfirmed":state.equals("STARTING")?"Connecting · apps not yet protected":state;
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
