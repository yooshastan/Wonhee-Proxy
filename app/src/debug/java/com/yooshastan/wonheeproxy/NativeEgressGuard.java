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
    private static final String PREFS="native_egress_guard_v1", KEY="owned_plan";
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
    static String staleStatus(Context c){return pending(c)?"Owned guard journal present · Stop or recover before Start":"No owned guard journal";}
    String status(){return status;}
    boolean failed(){return failed;}
    void install(String tun,String[] configs,boolean discovery,int validationPort)throws Exception{
        synchronized(LOCK){
            if(pending(context))throw new IllegalStateException("EGRESS_JOURNAL_PENDING");
            byte[] bytes=new byte[6];new SecureRandom().nextBytes(bytes);
            StringBuilder token=new StringBuilder();for(byte b:bytes)token.append(String.format(Locale.ROOT,"%02x",b&255));
            plan=new NativeEgressGuardPlan(token.toString(),tun,android.os.Process.myUid(),NativeEgressGuardPlan.DNS_IPV6,discovery,NativeEgressGuardPlan.endpoints(configs),validationPort);
            runtime.preflight(plan);
            if(plan.validationPlan()!=null)runtime.preflight(plan.validationPlan());
            if(!prefs(context).edit().putString(KEY,plan.encode()).commit())throw new IllegalStateException("EGRESS_JOURNAL_WRITE_FAILED");
            try{
                runtime.install(plan);
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
        try{return "Verified · "+runtime.counters(plan);}
        catch(Exception e){return "Verified · counters unavailable";}
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
            status=pending(context)?"Guard retained · offline recovery required":"Not installed";
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
                if(!prefs(context).edit().remove(KEY).commit())throw new IllegalStateException("EGRESS_JOURNAL_CLEAR_FAILED");
                status="Removed · exact-owned cleanup verified";plan=null;return true;
            }catch(Exception e){status="Cleanup unconfirmed · use offline guard recovery";return false;}
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
            if(p.validationPlan()!=null)runtime.remove(p.validationPlan());
            runtime.remove(p);
            if(!prefs(c).edit().remove(KEY).commit())throw new IllegalStateException("EGRESS_JOURNAL_CLEAR_FAILED");
            return "Owned guard removed and verified";
        }
    }
}
