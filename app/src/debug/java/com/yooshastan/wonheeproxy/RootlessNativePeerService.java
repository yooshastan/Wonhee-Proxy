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
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.provider.Settings;
import android.util.Log;

public final class RootlessNativePeerService extends VpnService {
    static final String START="com.yooshastan.wonheeproxy.PEER_START";
    static final String STOP="com.yooshastan.wonheeproxy.PEER_STOP";
    static final String PREFS="wonhee_peer_handshake_v1";
    private static final String TAG="WonheeNativePeers", CHANNEL="wonhee_peer_handshake";
    private final Handler handler=new Handler(Looper.getMainLooper());
    private final long[] handles=new long[3];
    private int count;
    private long deadline;
    private boolean registered,started,terminal,passed;
    private Network underlay;
    private String last="No peer result.";
    private String stage="preflight";
    private final Runnable poll=this::pollPeers;

    @Override public int onStartCommand(Intent intent,int flags,int id) {
        String action=intent==null?null:intent.getAction();
        if(STOP.equals(action)){finish("STOPPED");return START_NOT_STICKY;}
        if(!START.equals(action)){finish("STOPPED — no test requested");return START_NOT_STICKY;}
        if(started) return START_NOT_STICKY;
        started=true;
        try {
            Notification n=notification();
            if(Build.VERSION.SDK_INT>=34) startForeground(8401,n,ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
            else startForeground(8401,n);
            if(!RootlessNativeBridge.available() || VpnService.prepare(this)!=null
                    || !"off".equals(Settings.Global.getString(getContentResolver(),"private_dns_mode"))) throw new IllegalStateException();
            underlay=physicalNetwork();
            if(underlay==null) throw new IllegalStateException();
            stage="profile-validation";
            String[] configs=NativePeerProfiles.prepare(this,intent.getBooleanExtra("home",true),intent.getStringArrayExtra("overrides"));
            count=configs.length;
            stage="callback-registration";
            if(!RootlessNativeBridge.setVpnService(this)) throw new IllegalStateException();
            registered=true;
            for(int i=0;i<count;i++){
                stage="start-"+NativePeerProfiles.IDS[i];
                long h=RootlessNativeBridge.createPeerSession(NativePeerProfiles.IDS[i],configs[i]);
                if(h<=0){stage+="/native-code-"+h;throw new IllegalStateException();}
                handles[i]=h;
                configs[i]=null;
            }
            stage="socket-protection";
            long[] p=RootlessNativeBridge.protectionStats();
            if(p==null||p.length<2||p[0]!=2L*count||p[1]!=0) throw new IllegalStateException();
            deadline=SystemClock.elapsedRealtime()+90000L;
            stage="peer-handshakes";
            report("RUNNING — "+count+" independent peers; waiting for authenticated handshakes. No app routes.");
            handler.post(poll);
        } catch(NativePeerProfiles.Rejected failure) {
            finish("NOT PASSED — "+stage+"/"+failure.code);
        } catch(Exception|LinkageError failure) {finish("NOT PASSED — "+stage+" ("+failure.getClass().getSimpleName()+")");}
        return START_NOT_STICKY;
    }
    private Network physicalNetwork() {
        ConnectivityManager m=(ConnectivityManager)getSystemService(Context.CONNECTIVITY_SERVICE);
        if(m==null) return null;
        for(Network n:m.getAllNetworks()){
            NetworkCapabilities caps=m.getNetworkCapabilities(n);
            if(caps!=null&&caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return null;
        }
        Network n=m.getActiveNetwork();
        NetworkCapabilities c=n==null?null:m.getNetworkCapabilities(n);
        return c!=null&&(c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)||c.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR))?n:null;
    }
    private void pollPeers(){
        if(terminal) return;
        try {
            if(!underlay.equals(physicalNetwork()) || !"off".equals(Settings.Global.getString(getContentResolver(),"private_dns_mode"))) {finish("NOT PASSED — network or DNS setting changed");return;}
            long[] p=RootlessNativeBridge.protectionStats();
            if(p==null||p.length<2||p[0]!=2L*count||p[1]!=0){finish("NOT PASSED — protection counters changed");return;}
            boolean all=true;
            StringBuilder b=new StringBuilder();
            for(int i=0;i<count;i++){
                long[] s=RootlessNativeBridge.peerStats(handles[i]);
                if(s==null||s.length<3||s[0]<0||s[1]<0||s[2]<0){finish("NOT PASSED — peer statistics unavailable");return;}
                boolean ok=s[0]>0&&s[1]>0&&s[2]>0;
                all &= ok;
                b.append(NativePeerProfiles.SLOTS[i]).append(": ").append(ok?"HANDSHAKE VERIFIED":"awaiting handshake")
                    .append(" · RX=").append(s[1]).append(" TX=").append(s[2]).append(" bytes\n");
            }
            passed=all;
            last=(all?"PASS":"RUNNING")+" — "+count+" peers; protected sockets="+p[0]+"; failures="+p[1]+"\n"+b+"No TUN, app traffic, DNS, or payload forwarding.";
            report(last);
            if(SystemClock.elapsedRealtime()>=deadline){finish(all?"PASS — time limit reached":"NOT PASSED — handshake timeout");return;}
            handler.postDelayed(poll,1000L);
        } catch(Exception|LinkageError failure){finish("NOT PASSED — peer polling failed");}
    }
    private Notification notification(){
        NotificationManager m=(NotificationManager)getSystemService(NOTIFICATION_SERVICE);
        if(m!=null)m.createNotificationChannel(new NotificationChannel(CHANNEL,"Native peer handshake test",NotificationManager.IMPORTANCE_LOW));
        PendingIntent open=PendingIntent.getActivity(this,8401,new Intent(this,RootlessNativePeerActivity.class),PendingIntent.FLAG_IMMUTABLE|PendingIntent.FLAG_UPDATE_CURRENT);
        return new Notification.Builder(this,CHANNEL).setSmallIcon(R.drawable.ic_vpn_status).setContentTitle("Wonhee live peer test").setContentText("Handshake only · no app routing").setContentIntent(open).setOngoing(true).build();
    }
    private void report(String s){
        Log.i(TAG,s);
        getSharedPreferences(PREFS,MODE_PRIVATE).edit().putString("status",s).apply();
    }
    private boolean cleanup(){
        handler.removeCallbacks(poll);
        boolean ok=true;
        for(int i=handles.length-1;i>=0;i--) if(handles[i]>0){
            try{if(!RootlessNativeBridge.closeSession(handles[i]))ok=false;}
            catch(RuntimeException|LinkageError failure){ok=false;}
            handles[i]=0;
        }
        if(registered){
            try{if(!RootlessNativeBridge.clearVpnService(this))ok=false;}
            catch(RuntimeException|LinkageError failure){ok=false;}
            registered=false;
        }
        stopForeground(STOP_FOREGROUND_REMOVE);
        return ok;
    }
    private void finish(String reason){
        if(terminal)return;terminal=true;
        boolean ok=cleanup();
        report(reason+" — "+(ok?"native peer sessions released":"cleanup unconfirmed; force stop this diagnostic app")+"\nLast report:\n"+last);
        stopSelf();
    }
    @Override public void onRevoke(){finish("STOPPED — VPN permission revoked");}
    @Override public void onDestroy(){if(!terminal){terminal=true;boolean ok=cleanup();report("STOPPED unexpectedly — "+(ok?"sessions released":"cleanup unconfirmed")+"\n"+last);}super.onDestroy();}
}
