package com.yooshastan.wonheeproxy;

import android.content.Context;
import android.content.SharedPreferences;
import com.wireguard.android.util.RootShell;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.*;

/** Opt-in experiment for VpnService sessions. Journal persists across process death.
 * Guard remains on failure/recovery until explicit Stop; not a boot-persistent kill switch. */
final class NativeEgressGuard {
    private static final String PREFS="native_egress_guard_v1", KEY="owned_plan", BOOT="owned_boot_count", RECEIPT="last_cleanup", RECEIPT_AT="last_cleanup_at";
    private static final Object LOCK=new Object();
    private final Context context;
    private final NativeEgressGuardRuntime runtime;
    private final ScheduledExecutorService auditor=Executors.newSingleThreadScheduledExecutor();
    private NativeEgressGuardPlan plan;
    private volatile String status="Not installed";
    private volatile boolean failed,closing;
    NativeEgressGuard(Context context){
        this.context=context.getApplicationContext();
        RootShell shell=new RootShell(this.context);
        runtime=new NativeEgressGuardRuntime(shell::run);
    }
    private static SharedPreferences prefs(Context c){return c.getSharedPreferences(PREFS,Context.MODE_PRIVATE);}
    static boolean pending(Context c){return prefs(c).contains(KEY);}
    private static int bootCount(Context c){
        try{return android.provider.Settings.Global.getInt(c.getContentResolver(),android.provider.Settings.Global.BOOT_COUNT,-1);}
        catch(RuntimeException e){return -1;}
    }
    private static String bootEvidence(Context c){
        int old=prefs(c).getInt(BOOT,-1),now=bootCount(c);
        return old<0||now<0?"Boot continuity unknown (legacy or unavailable)":old==now?"Same boot as installation":"Boot changed since installation";
    }
    private static String lastCleanup(Context c){
        String receipt=prefs(c).getString(RECEIPT,"No cleanup receipt recorded");
        long at=prefs(c).getLong(RECEIPT_AT,0);
        return receipt+(at>0?" · "+new java.util.Date(at):"");
    }
    private static boolean clearJournal(Context c,String receipt){
        return prefs(c).edit().remove(KEY).remove(BOOT).putString(RECEIPT,receipt)
            .putLong(RECEIPT_AT,System.currentTimeMillis()).commit();
    }
    static String staleStatus(Context c){return pending(c)?"Owned guard journal present · protection unconfirmed · inspect or recover before Start · "+bootEvidence(c):"No owned guard journal · "+lastCleanup(c);}
    String status(){return status;}
    boolean failed(){return failed;}
    // Read-only capability check before Android captures apps. A nonzero
    // IPv6 NAT listing means unavailable/unverified, not a filter exemption.
    static boolean validationDualAvailable(Context context)throws Exception{
        RootShell shell=new RootShell(context.getApplicationContext());
        List<String> out=new ArrayList<>();
        if(shell.run(out,"iptables -w 3 -t nat -S")!=0||out.stream().noneMatch(x->x.startsWith("-P OUTPUT ")))
            throw new NativePeerProfiles.Rejected("VALIDATION_IPV4_NAT_UNAVAILABLE");
        out.clear();
        return shell.run(out,"ip6tables -w 3 -t nat -S")==0&&out.stream().anyMatch(x->x.startsWith("-P OUTPUT "));
    }
    void install(String tun,String[] configs,boolean discovery,int validationPort,boolean validationDual,boolean strictIp)throws Exception{
        synchronized(LOCK){
            if(pending(context))throw new IllegalStateException("EGRESS_JOURNAL_PENDING");
            if(strictIp&&(discovery||validationPort!=0))throw new IllegalStateException("EGRESS_STRICT_CONFIG_REFUSED");
            byte[] bytes=new byte[6];new SecureRandom().nextBytes(bytes);
            StringBuilder token=new StringBuilder();for(byte b:bytes)token.append(String.format(Locale.ROOT,"%02x",b&255));
            plan=new NativeEgressGuardPlan(token.toString(),tun,android.os.Process.myUid(),strictIp?NativeEgressGuardPlan.STRICT_IP:NativeEgressGuardPlan.DNS_IPV6,discovery,NativeEgressGuardPlan.endpoints(configs),validationPort,true,validationDual,validationPort!=0);
            runtime.preflight(plan);
            if(plan.validationPlan()!=null)runtime.preflight(plan.validationPlan());
            if(!prefs(context).edit().putString(KEY,plan.encode()).putInt(BOOT,bootCount(context)).commit())throw new IllegalStateException("EGRESS_JOURNAL_WRITE_FAILED");
            try{
                if(strictIp)runtime.installStrict(plan);else runtime.install(plan);
                if(plan.validationPlan()!=null)runtime.installValidation(plan.validationPlan());
                status=verifiedStatus();
                auditor.scheduleWithFixedDelay(this::audit,5,5,TimeUnit.SECONDS);
            }catch(Exception error){
                failed=true;status="Install unconfirmed · Stop to remove exact owned rules";
                throw error;
            }
        }
    }
    // Counter presentation is diagnostic, not the verified rule integrity check.
    private String verifiedStatus(){
        String result;
        try{result="Verified · "+runtime.counters(plan);}
        catch(Exception e){result="Verified · filter counters unavailable";}
        if(plan.mode==NativeEgressGuardPlan.STRICT_IP)result+=" · strict IP preview";
        if(plan.validationPlan()!=null){
            try{result+=" · "+runtime.validationCounters(plan.validationPlan());}
            catch(Exception e){result+=" · NAT counters unavailable";}
        }else result+=" · NAT redirect off";
        return result;
    }
    private void audit(){
        synchronized(LOCK){
            if(closing||plan==null||failed)return;
            try{
                runtime.verify(plan);if(plan.validationPlan()!=null)runtime.verify(plan.validationPlan());status=verifiedStatus();
            }catch(Exception error){
                failed=true;status="Verification failed · captured traffic held; protection unconfirmed";
            }
        }
    }
    void retain(){
        closing=true;auditor.shutdown();
        synchronized(LOCK){
            // Unexpected orderly teardown: try removing the NAT redirect before
            // closing the listener. Keep the original journal for offline cleanup.
            if(plan!=null&&plan.validationPlan()!=null)try{runtime.remove(plan.validationPlan());}
            catch(Exception ignored){}
            status=pending(context)?"Guard journal retained · kernel protection unconfirmed · inspect or recover offline":"Not installed";
        }
    }
    boolean remove(){
        closing=true;auditor.shutdown();
        synchronized(LOCK){
            try{
                // Never clear a mismatching or unreadable persistent record.
                String data=prefs(context).getString(KEY,null);
                if(data==null){status="Not installed";return true;}
                if(plan==null||!plan.encode().equals(data))throw new IllegalStateException("EGRESS_JOURNAL_MISMATCH");
                if(plan.validationPlan()!=null)runtime.remove(plan.validationPlan());
                runtime.remove(plan);
                if(!clearJournal(context,"Explicit Stop: owned rules absent after cleanup"))throw new IllegalStateException("EGRESS_JOURNAL_CLEAR_FAILED");
                status="Removed · exact-owned cleanup verified";plan=null;return true;
            }catch(Exception e){status="Cleanup unconfirmed · use offline guard recovery";return false;}
        }
    }
    static String inspectOffline(Context c)throws Exception{
        synchronized(LOCK){
            if(NativeAppRoutingService.running())throw new IllegalStateException("STOP_VPN_FIRST");
            String data=prefs(c).getString(KEY,null);
            if(data==null)return "No owned guard journal; protection unconfirmed · "+lastCleanup(c);
            NativeEgressGuardPlan p=NativeEgressGuardPlan.decode(data);
            RootShell shell=new RootShell(c.getApplicationContext());
            NativeEgressGuardRuntime runtime=new NativeEgressGuardRuntime(shell::run);
            String filter=runtime.offlineState(p);
            String nat=p.validationPlan()==null?"Not configured":runtime.offlineState(p.validationPlan());
            String counters="Counters unavailable unless filter integrity is verified";
            if(filter.equals("Exact rules and first anchors present")){
                try{counters=runtime.counters(p);runtime.verify(p);}
                catch(Exception e){counters="Counters or subsequent verification unconfirmed";filter="Verification unconfirmed";}
            }
            return (p.mode==NativeEgressGuardPlan.STRICT_IP?"Strict IP preview":"DNS/IPv6 guard")
                +" · filter: "+filter+" · NAT: "+nat+"\n"+bootEvidence(c)+"\n"+counters
                +"\nJournal retained; counters are cumulative, packet protection not proven";

        }
    }
    static String recover(Context c)throws Exception{
        synchronized(LOCK){
            if(NativeAppRoutingService.running())throw new IllegalStateException("STOP_VPN_FIRST");
            String data=prefs(c).getString(KEY,null);
            if(data==null)return "No owned guard journal";
            NativeEgressGuardPlan p=NativeEgressGuardPlan.decode(data);
            RootShell shell=new RootShell(c.getApplicationContext());
            NativeEgressGuardRuntime runtime=new NativeEgressGuardRuntime(shell::run);
            String before=runtime.offlineState(p);
            if(p.validationPlan()!=null)runtime.remove(p.validationPlan());
            runtime.remove(p);
            if(!clearJournal(c,"Explicit offline recovery: prior filter "+before+"; owned rules absent after cleanup"))throw new IllegalStateException("EGRESS_JOURNAL_CLEAR_FAILED");
            return "Owned guard removed and verified";
        }
    }
}
