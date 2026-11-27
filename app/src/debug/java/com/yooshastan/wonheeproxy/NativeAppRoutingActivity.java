package com.yooshastan.wonheeproxy;

import android.app.Activity;
import android.content.*;
import android.content.pm.ResolveInfo;
import android.net.VpnService;
import android.os.Bundle;
import android.view.View;
import android.widget.*;
import java.io.InputStream;
import java.util.*;

public final class NativeAppRoutingActivity extends Activity {
    private static final int VPN=8300,IMPORT=8310,HOSTS=8320,EXPORT_RULES=8340,IMPORT_RULES=8341;
    private static final String[] CHOICES={"Inherit","Exit A","Exit B","Block"};
    private static final int[] VALUES={NativeAppRoutingPolicy.INHERIT,0,1,-1};
    private final List<AppRow> apps=new ArrayList<>();
    private final Spinner[] categories=new Spinner[AppUseCategories.LABELS.length];
    private final Spinner[] protocols=new Spinner[NativeAppRoutingPolicy.SELECTORS.length];
    private final EditText[] overrides=new EditText[3];
    private TextView status,profiles,headline,speed,blocked,summary,sectionTitle,notice,underlayStatus;
    private Button startButton,stopButton;
    private final LinearLayout[] pages=new LinearLayout[5];
    private final Button[] tabs=new Button[5];
    private ScrollView scroll;
    private int page=0;
    private final android.os.Handler ui=new android.os.Handler(android.os.Looper.getMainLooper());
    private final Runnable tick=new Runnable(){public void run(){updateLive();ui.postDelayed(this,1000);}};
    private boolean readingHosts, draftReady;
    private long hostsGeneration;
    private static final int BG=0xfff8f3ff, INK=0xff312446, ACCENT=0xff7051aa, SURFACE=0xffeee4fa, PINK=0xfff4ddec;
    private static final String[] SECTIONS={"Home","Tunnels","Routing","Protection","Activity"};
    private EditText homeCidr;
    private CheckBox home,allApps;
    private Spinner fallback,dnsProvider,dnsRole,dnsMode,dnsAlternate,networkPreference,bootstrapOption,dnsStrategy;
    private CheckBox hostsEnabled,blockExternal853,autoRecovery,rootEgressGuard,rootLocalDiscovery;
    private TextView rootGuardStatus;
    private Button rootRecoverButton;
    private boolean rootRecoveryBusy;
    private TextView hostsStatus,dnsHealth,dnsPending;
    private Button dnsTestButton,functionalTestButton;
    private TextView functionalStatus;
    private android.content.SharedPreferences draft;
    private static final class AppRow {
        final String pkg;final CheckBox selected;final Spinner category,role;final int suggested;
        AppRow(String p,CheckBox s,Spinner c,Spinner r,int suggestion){pkg=p;selected=s;category=c;role=r;suggested=suggestion;}
    }
    @Override public void onCreate(Bundle state){
        super.onCreate(state);
        draft=getSharedPreferences("native_app_route_draft_v1",MODE_PRIVATE);
        LinearLayout shell=new LinearLayout(this);shell.setOrientation(LinearLayout.VERTICAL);shell.setBackgroundColor(BG);
        shell.setFitsSystemWindows(true);
        LinearLayout header=new LinearLayout(this);header.setOrientation(LinearLayout.VERTICAL);header.setPadding(dp(18),dp(12),dp(18),dp(6));shell.addView(header);
        TextView brand=label(header,"wonhee  ✦",26);brand.setTypeface(null,android.graphics.Typeface.BOLD);
        label(header,"PROXY  /  0.26.0 PREVIEW",12);
        LinearLayout nav=new LinearLayout(this);nav.setOrientation(LinearLayout.HORIZONTAL);nav.setPadding(dp(6),0,dp(6),0);shell.addView(nav);
        for(int i=0;i<tabs.length;i++){
            final int at=i;Button t=new Button(this);t.setAllCaps(false);t.setText(i==3?"Protect":SECTIONS[i]);t.setContentDescription(SECTIONS[i]);t.setSingleLine(true);t.setAutoSizeTextTypeUniformWithConfiguration(8,11,1,android.util.TypedValue.COMPLEX_UNIT_SP);t.setMinWidth(0);t.setMinimumWidth(0);t.setPadding(dp(2),0,dp(2),0);
            t.setOnClickListener(v->showPage(at));nav.addView(t,new LinearLayout.LayoutParams(0,dp(48),1));tabs[i]=t;
        }
        scroll=new ScrollView(this);scroll.setFillViewport(true);shell.addView(scroll,new LinearLayout.LayoutParams(-1,0,1));
        android.widget.FrameLayout holder=new android.widget.FrameLayout(this);scroll.addView(holder);
        for(int i=0;i<pages.length;i++){
            LinearLayout v=new LinearLayout(this);v.setOrientation(LinearLayout.VERTICAL);v.setPadding(dp(16),dp(12),dp(16),dp(24));pages[i]=v;holder.addView(v,new android.widget.FrameLayout.LayoutParams(-1,-2));
        }
        LinearLayout root=pages[0];
        headline=label(root,"Disconnected",25);headline.setTypeface(null,android.graphics.Typeface.BOLD);headline.setPadding(dp(14),dp(16),dp(14),dp(8));headline.setBackground(round(SURFACE,18));
        underlayStatus=label(root,"Physical connection · disconnected",14);
        speed=label(root,"↓ 0 B/s   ↑ 0 B/s",20);speed.setPadding(dp(12),dp(12),dp(12),dp(8));
        blocked=label(root,"Blocked DNS · 0",17);blocked.setPadding(dp(12),dp(8),dp(12),dp(12));blocked.setBackground(round(PINK,14));
        startButton=button(root,"Start connection",()->{
            try{makeIntent();save();Intent consent=VpnService.prepare(this);if(consent!=null)startActivityForResult(consent,VPN);else launch();}
            catch(Exception e){notice.setText("Start refused: "+preflightReason(e));}
        });startButton.setBackgroundTintList(android.content.res.ColorStateList.valueOf(ACCENT));startButton.setTextColor(0xffffffff);
        stopButton=button(root,"Stop connection",()->startService(new Intent(this,NativeAppRoutingService.class).setAction(NativeAppRoutingService.STOP)));
        notice=label(root,"",14);
        summary=label(root,"",15);
        button(root,"Tunnels · import or change",()->showPage(1));
        button(root,"Routing · choose apps and exits",()->showPage(2));
        button(root,"Protection · DNS, hosts and egress",()->showPage(3));
        button(root,"Activity · connection details",()->showPage(4));
        label(root,"Choose all-app preview or selected-app testing in Routing. Protection starts only after VPN establishment. Private DNS must remain OFF.",13);
        button(root,"Enable traffic notification",()->{if(android.os.Build.VERSION.SDK_INT>=33&&checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS)!=android.content.pm.PackageManager.PERMISSION_GRANTED)requestPermissions(new String[]{android.Manifest.permission.POST_NOTIFICATIONS},8330);else notice.setText("Notification permission already available.");});
        root=pages[1];
        label(root,"Tunnels",23);
        label(root,"Secure endpoint bootstrap (before VPN)",15);
        bootstrapOption=spinner(root,NativeEndpointBootstrap.OPTIONS,draft.getInt("bootstrapOption",0));
        label(root,"Default Cloudflare DoH is the tested control. Alternatives are explicit, no fallback. Numeric overrides skip endpoint DNS.",13);
        label(root,"Physical connection preference",15);
        networkPreference=spinner(root,NativeUnderlayPolicy.LABELS,draft.getInt("networkPreference",NativeUnderlayPolicy.WIFI_FIRST));
        label(root,"Wi-Fi or cellular preferences use the other validated physical network if needed. Android best available uses Android's best physical match where supported. Maintain current switches only on loss. Migration requires automatic recovery. Changes apply on next Start.",13);
        profiles=label(root,"",14);
        for(int i=0;i<3;i++){
            final int slot=i;
            button(root,"Import "+NativePeerProfiles.SLOTS[i],()->startActivityForResult(new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("*/*").addCategory(Intent.CATEGORY_OPENABLE),IMPORT+slot));
            EditText ip=new EditText(this);ip.setSingleLine(true);ip.setSaveEnabled(false);ip.setHint("Optional numeric override; blank = secure DNS");ip.setText(draft.getString("endpointOverride"+i,""));overrides[i]=ip;root.addView(ip);
        }
        home=new CheckBox(this);home.setText("Include Home private route");home.setChecked(draft.getBoolean("home",true));root.addView(home);
        homeCidr=new EditText(this);homeCidr.setSingleLine(true);homeCidr.setHint("Private Home IPv4 CIDR");homeCidr.setText(draft.getString("homeCidr","10.0.0.169/32"));root.addView(homeCidr);
        button(root,"Choose authorized Home route",this::pickHomeRoute);
        label(root,"Default Internet exit",15);fallback=spinner(root,new String[]{"Exit A","Exit B"},draft.getInt("default",0));
        button(root,"Save & return home",()->{save();showPage(0);});
        root=pages[3];
        label(root,"Protection",23);
        label(root,"Local UDP and TCP DNS use the selected authenticated encrypted transport and DNS routing strategy. DoT and QUIC reuse authenticated connections. No transport fallback. Application-owned DoH is not intercepted. Captured IPv6 is blocked. The default guard is in-process only; the optional root trial below covers additional physical egress.",14);
        autoRecovery=new CheckBox(this);autoRecovery.setText("Recover tunnels automatically while VPN remains established");autoRecovery.setChecked(draft.getBoolean("autoRecovery",true));root.addView(autoRecovery);
        label(root,"Recovery keeps selected apps inside the existing TUN. It uses the current session's endpoints and stops after five attempts. No protection guarantee if Android revokes or kills VPN.",13);
        label(root,"Root egress guard · experimental",18);
        rootEgressGuard=new CheckBox(this);rootEgressGuard.setText("Block direct DNS and IPv6 outside Wonhee (root)");rootEgressGuard.setChecked(draft.getBoolean("rootEgressGuard",false));root.addView(rootEgressGuard);
        rootLocalDiscovery=new CheckBox(this);rootLocalDiscovery.setText("Allow direct mDNS and SSDP discovery");rootLocalDiscovery.setChecked(draft.getBoolean("rootLocalDiscovery",false));root.addView(rootLocalDiscovery);
        label(root,"Requires root and all-app capture. Installs only after VPN establishment; blocks direct port 53/853 and IPv6 data, except exact WireGuard endpoints and narrow local control. Other direct IPv4 remains allowed. IPv4 IPsec is unchanged; carrier DNS and IPv6 calls may be affected. No broad IPv4 lockdown. Stop to remove the guard. Unexpected process death can leave rules installed; use recovery below. AFWall+ is not changed. A firewall reload can remove or move the guard; periodic verification holds captured traffic on detection.",13);
        rootGuardStatus=label(root,"Root guard · not active",14);
        rootRecoverButton=button(root,"Recover owned root guard (offline)",()->{
            if(rootRecoveryBusy||NativeAppRoutingService.running())return;
            new android.app.AlertDialog.Builder(this).setTitle("Remove owned guard rules?")
                .setMessage("Only exact journaled Wonhee rules are removed. Normal networking may resume without VPN protection. Stop any active Wonhee connection first.")
                .setPositiveButton("Recover",(d,b)->{
                    rootRecoveryBusy=true;updateLive();
                    new Thread(()->{
                        String msg;
                        try{msg=NativeEgressGuard.recover(this);}
                        catch(Exception e){msg="Root guard recovery refused or unconfirmed; journal retained";}
                        final String result=msg;
                        runOnUiThread(()->{rootRecoveryBusy=false;notice.setText(result);updateLive();});
                    }).start();
                }).setNegativeButton("Cancel",null).show();
        });
        label(root,"Encrypted DNS protocol",14);
        dnsMode=spinner(root,NativeDnsTransportPolicy.LABELS,draft.getInt("dnsMode",0));
        label(root,"DoT: all four providers. DoQ: Quad9 or AdGuard. DoH3: Cloudflare, Quad9 or AdGuard (experimental). Unsupported combinations are refused; select a supported provider before Start. Endpoint bootstrap is configured separately in Tunnels. No plaintext fallback.",13);
        label(root,"Encrypted DNS provider",14);
        dnsProvider=spinner(root,NativeProtectedDnsRelay.NAMES,draft.getInt("dnsProvider",0));
        label(root,"Managed DNS routing",14);
        dnsStrategy=spinner(root,new String[]{"Global · one DNS exit","Follow app/DNS rules · shared resolver exit","Strict · deny unattributed DNS"},draft.getInt("dnsStrategy",0));
        label(root,"Follow uses the app's active route or explicit DNS port override. Android can hide the originating app behind a shared resolver. Follow sends these unattributed queries through the selected shared DNS exit; Strict drops them and may break Android DNS. Both split modes use separate encrypted caches/connections per exit. No failover.",13);
        label(root,"Global / shared resolver exit (unused in Strict)",14);
        dnsRole=spinner(root,new String[]{"Exit A","Exit B"},draft.getInt("dnsRole",0));
        label(root,"Provider address",14);
        dnsAlternate=spinner(root,new String[]{"Primary address","Secondary address"},draft.getInt("dnsAlternate",0));
        label(root,"Selections below are for the next Start. No automatic provider, address, exit or protocol fallback.",13);
        dnsPending=label(root,"Configured DNS · not active",14);
        dnsHealth=label(root,"DNS health · not active",14);
        dnsTestButton=button(root,"Test active DNS provider",()->startService(new Intent(this,NativeAppRoutingService.class).setAction(NativeAppRoutingService.DNS_TEST)));
        label(root,"Tests example.com through each active non-held encrypted DNS relay without using cache or HOSTS. Does not apply draft settings. Start the desired configuration first.",13);
        functionalTestButton=button(root,"Test TCP DNS and HOSTS",()->startService(new Intent(this,NativeAppRoutingService.class).setAction(NativeAppRoutingService.DNS_FUNCTIONAL_TEST)));
        functionalStatus=label(root,"Functional DNS test · not active",14);
        label(root,"Uses the active VPN virtual TCP resolver on each non-held DNS exit, a local HOSTS entry and a fixed public test name. No direct DNS or transport fallback. Public answer may use cache.",13);
        blockExternal853=new CheckBox(this);blockExternal853.setText("Block app-owned TCP/UDP port 853");blockExternal853.setChecked(draft.getBoolean("blockExternal853",true));root.addView(blockExternal853);
        hostsEnabled=new CheckBox(this);hostsEnabled.setText("Enable imported hosts filtering");hostsEnabled.setChecked(draft.getBoolean("hostsEnabled",false));root.addView(hostsEnabled);
        hostsStatus=label(root,"",14);
        button(root,"Import HOSTS / domain list",()->startActivityForResult(new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("*/*").addCategory(Intent.CATEGORY_OPENABLE),HOSTS));
        button(root,"Restore previous hosts list",()->new Thread(()->{
            try{RootBlocklistStore.restorePrevious(getFilesDir());runOnUiThread(this::refresh);}
            catch(Exception e){runOnUiThread(()->hostsStatus.setText("Restore refused: no valid previous list"));}
        },"WonheeHostsRestore").start());
        button(root,"Save & return home",()->{save();showPage(0);});
        root=pages[2];
        label(root,"Routing",23);
        allApps=new CheckBox(this);allApps.setText("Capture all apps in this Android user (preview)");allApps.setChecked(draft.getBoolean("allApps",false));root.addView(allApps);
        allApps.setOnCheckedChangeListener((v,on)->{if(on)new android.app.AlertDialog.Builder(this).setTitle("All-app preview").setMessage("All app traffic in this Android user is captured after VPN startup. Unknown owners, conflicting shared UIDs, unsupported protocols and IPv6 are blocked. Some system or LAN services may stop working. Stop restores normal networking. Not an always-on kill switch.").setPositiveButton("Use all-app preview",(d,b)->autoSave()).setNegativeButton("Keep selected apps",(d,b)->allApps.setChecked(false)).setOnCancelListener(d->allApps.setChecked(false)).show();else autoSave();});
        label(root,"Default Internet exit · change in Tunnels",14);
        button(root,"Export routing rules (JSON)",()->{save();startActivityForResult(new Intent(Intent.ACTION_CREATE_DOCUMENT).setType("application/json").addCategory(Intent.CATEGORY_OPENABLE).putExtra(Intent.EXTRA_TITLE,"wonhee-routing-v1.json"),EXPORT_RULES);});
        button(root,"Import routing rules (JSON)",()->new android.app.AlertDialog.Builder(this).setTitle("Restore routing rules?").setMessage("Replaces saved routing choices. Tunnel credentials and DNS settings are not included. Active VPN rules stay unchanged until the next Start.").setPositiveButton("Choose file",(d,b)->startActivityForResult(new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("*/*").addCategory(Intent.CATEGORY_OPENABLE),IMPORT_RULES)).setNegativeButton("Cancel",null).show());
        label(root,"Categories",18);
        label(root,"Explicit blocks win, then authorized Home destinations. Assign categories to Exit A or B, inherit default, or block traffic.",14);
        for(int i=0;i<categories.length;i++){
            label(root,AppUseCategories.LABELS[i],14);categories[i]=spinner(root,CHOICES,draft.getInt("cat"+i,0));
        }
        label(root,"Protocol overrides",18);
        label(root,"Public TCP/UDP destination-port rules override category and app routes. Explicit blocks win; managed DNS follows the Protection routing strategy. Port names are hints, not protocol detection.",14);
        for(int i=0;i<protocols.length;i++){
            label(root,NativeAppRoutingPolicy.SELECTOR_NAMES[i],14);protocols[i]=spinner(root,CHOICES,draft.getInt("proto"+i,0));
        }
        label(root,"Installed applications",18);
        label(root,"All-app mode needs no checked apps. Use checkboxes only to expand individual exceptions or select apps in the limited test mode. Changes apply at next Start.",14);
        button(root,"Use recommended all-app capture",()->{if(!allApps.isChecked())allApps.setChecked(true);});
        button(root,"Clear selected apps",()->{for(AppRow a:apps)a.selected.setChecked(false);});
        button(root,"Reset categories to automatic suggestions",()->new android.app.AlertDialog.Builder(this).setTitle("Reset app categories?").setMessage("Replaces manual category choices for visible apps; individual exit overrides are retained.").setPositiveButton("Reset",(d,b)->{for(AppRow a:apps)try{android.content.pm.ApplicationInfo info=getPackageManager().getApplicationInfo(a.pkg,0);a.category.setSelection(NativeAppCategorySuggestions.suggest(a.pkg,info.category,(info.flags&android.content.pm.ApplicationInfo.FLAG_SYSTEM)!=0));}catch(Exception ignored){}}).setNegativeButton("Cancel",null).show());
        EditText filter=new EditText(this);filter.setSingleLine(true);filter.setHint("Search installed apps");root.addView(filter);
        LinearLayout appList=new LinearLayout(this);appList.setOrientation(LinearLayout.VERTICAL);root.addView(appList);
        final Map<View,String> searchRows=new LinkedHashMap<>();
        List<ResolveInfo> visible=getPackageManager().queryIntentActivities(new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER),0);
        visible.sort(Comparator.comparing(r->r.loadLabel(getPackageManager()).toString(),String.CASE_INSENSITIVE_ORDER));
        Set<String> seen=new HashSet<>();
        for(ResolveInfo r:visible){
            if(r.activityInfo==null)continue;String pkg=r.activityInfo.packageName;
            if(pkg.equals(getPackageName())||!AppUseCategories.validPackageName(pkg)||!seen.add(pkg))continue;
            CheckBox selected=new CheckBox(this);selected.setText(r.loadLabel(getPackageManager())+" ("+pkg+")");
            selected.setChecked(draft.getBoolean("selected:"+pkg,false));
            LinearLayout appCard=new LinearLayout(this);appCard.setOrientation(LinearLayout.VERTICAL);appCard.addView(selected);appList.addView(appCard);searchRows.put(appCard,selected.getText().toString().toLowerCase(Locale.ROOT));
            LinearLayout detail=new LinearLayout(this);detail.setOrientation(LinearLayout.VERTICAL);
            int suggested=NativeAppCategorySuggestions.suggest(pkg,r.activityInfo.applicationInfo.category,(r.activityInfo.applicationInfo.flags&android.content.pm.ApplicationInfo.FLAG_SYSTEM)!=0);
            label(detail,"Category (suggested: "+AppUseCategories.label(suggested)+")",13);Spinner category=spinner(detail,AppUseCategories.LABELS,draft.getInt("category:"+pkg,suggested));
            label(detail,"Individual exit override",13);Spinner role=spinner(detail,CHOICES,draft.getInt("role:"+pkg,0));
            appCard.addView(detail);detail.setVisibility(selected.isChecked()?View.VISIBLE:View.GONE);
            selected.setOnCheckedChangeListener((v,checked)->{detail.setVisibility(checked?View.VISIBLE:View.GONE);autoSave();});
            apps.add(new AppRow(pkg,selected,category,role,suggested));
        }
        filter.addTextChangedListener(new android.text.TextWatcher(){
            public void beforeTextChanged(CharSequence x,int st,int c,int after){}
            public void onTextChanged(CharSequence x,int st,int before,int c){String q=x.toString().trim().toLowerCase(Locale.ROOT);for(Map.Entry<View,String> e:searchRows.entrySet())e.getKey().setVisibility(e.getValue().contains(q)?View.VISIBLE:View.GONE);}
            public void afterTextChanged(android.text.Editable x){}
        });
        button(root,"Check configuration (offline)",()->{try{makeIntent();notice.setText("Offline configuration passed. Network/TLS/peer tests run at Start.");}catch(Exception e){notice.setText("Configuration refused: "+preflightReason(e));}showPage(0);});
        button(root,"Save & return home",()->{save();notice.setText("Saved. Stop and Start to apply changes.");showPage(0);});
        root=pages[4];
        label(root,"Activity",23);
        label(root,"Routing evidence · open two browsers assigned to different exits, test their public IPs, and stream Moka. Per-port flow counts below show admitted connections, not verified remote identities.",13);
        status=label(root,"",14);
        button(root,"Copy redacted diagnostics",()->{
            android.content.ClipboardManager clipboard=(android.content.ClipboardManager)getSystemService(CLIPBOARD_SERVICE);
            if(clipboard!=null)clipboard.setPrimaryClip(ClipData.newPlainText("Wonhee diagnostics",getSharedPreferences(NativeAppRoutingService.PREFS,MODE_PRIVATE).getString("status","Not started")));
        });
        button(root,"Test one route held (90 seconds)",()->new android.app.AlertDialog.Builder(this).setTitle("Route isolation simulation").setItems(new String[]{"Exit A","Exit B","Home"},(d,role)->new android.app.AlertDialog.Builder(this).setMessage("Temporarily drop traffic assigned to this route without changing its peer or rerouting packets. In Global DNS mode the configured DNS exit cannot be held. In split modes DNS traffic assigned to the held exit is blocked too. Other routes should continue. The timer is 90 seconds.").setPositiveButton("Test",(x,b)->startService(new Intent(this,NativeAppRoutingService.class).setAction(NativeAppRoutingService.ISOLATION_TEST).putExtra("role",role))).setNegativeButton("Cancel",null).show()).setNegativeButton("Cancel",null).show());
        button(root,"End route isolation test",()->startService(new Intent(this,NativeAppRoutingService.class).setAction(NativeAppRoutingService.ISOLATION_TEST).putExtra("role",-1)));
        button(root,"Test automatic recovery",()->new android.app.AlertDialog.Builder(this).setTitle("Test tunnel recovery?").setMessage("Restarts peer sessions while keeping the existing VPN. Selected apps may temporarily lose connectivity. Enable automatic recovery and restart first.").setPositiveButton("Test",(d,b)->startService(new Intent(this,NativeAppRoutingService.class).setAction(NativeAppRoutingService.RECOVERY_TEST))).setNegativeButton("Cancel",null).show());
        button(root,"Simulate tunnel failure (test guard)",()->new android.app.AlertDialog.Builder(this).setTitle("Test failure guard?").setMessage("This deliberately interrupts captured traffic until you press Stop.").setPositiveButton("Test",(d,b)->startService(new Intent(this,NativeAppRoutingService.class).setAction(NativeAppRoutingService.GUARD_TEST))).setNegativeButton("Cancel",null).show());
        button(root,"Return home",()->showPage(0));
        button(root,"Advanced diagnostics",()->new android.app.AlertDialog.Builder(this)
            .setTitle("Advanced diagnostics — stop VPN first")
            .setItems(new String[]{"Native transfer regression","Read-only readiness","Legacy kernel lab / Safe Stop"},(dialog,index)->{
                Class<?> target=index==0?RootlessNativePeerActivity.class:index==1?RootlabReadinessActivity.class:RootlabTwoPeerActivity.class;
                if(index==2)new android.app.AlertDialog.Builder(this).setTitle("Legacy kernel laboratory").setMessage("This is not the current connection screen. Use only for deliberate diagnostics or exact-owned Safe Stop of old root links. Do not start it while protected routing is active.").setPositiveButton("Open legacy lab",(d,b)->startActivity(new Intent(this,target))).setNegativeButton("Cancel",null).show();
                else startActivity(new Intent(this,target));
            }).setNegativeButton("Cancel",null).show());
        setContentView(shell);wireDraftAutosave();showPage(0);refresh();
    }
    private int dp(int n){return (int)(n*getResources().getDisplayMetrics().density+0.5f);}
    private android.graphics.drawable.GradientDrawable round(int color,int radius){android.graphics.drawable.GradientDrawable d=new android.graphics.drawable.GradientDrawable();d.setColor(color);d.setCornerRadius(dp(radius));return d;}
    private TextView label(LinearLayout root,String value,int size){TextView v=new TextView(this);v.setText(value);v.setTextColor(INK);v.setTextSize(size);v.setPadding(0,dp(5),0,dp(5));root.addView(v);return v;}
    private Button button(LinearLayout root,String value,Runnable action){Button b=new Button(this);b.setAllCaps(false);b.setText(value);b.setTextColor(INK);b.setBackgroundTintList(android.content.res.ColorStateList.valueOf(SURFACE));b.setOnClickListener(v->action.run());root.addView(b);return b;}
    private void showPage(int next){page=next;for(int i=0;i<pages.length;i++){pages[i].setVisibility(i==next?View.VISIBLE:View.GONE);tabs[i].setBackgroundTintList(android.content.res.ColorStateList.valueOf(i==next?ACCENT:SURFACE));tabs[i].setTextColor(i==next?0xffffffff:INK);}scroll.scrollTo(0,0);updateLive();}
    @Override protected void onResume(){super.onResume();ui.removeCallbacks(tick);ui.post(tick);}
    @Override protected void onPause(){ui.removeCallbacks(tick);autoSave();super.onPause();}
    @Override public void onBackPressed(){if(page!=0)showPage(0);else super.onBackPressed();}
    private void updateLive(){
        if(headline==null||status==null)return;
        android.content.SharedPreferences prefs=getSharedPreferences(NativeAppRoutingService.PREFS,MODE_PRIVATE);
        String state=prefs.getString("state","IDLE"),report=prefs.getString("status","Not started");
        long age=android.os.SystemClock.elapsedRealtime()-prefs.getLong("heartbeat",0);
        if(!NativeAppRoutingService.running()&&(state.equals("ACTIVE")||state.equals("BLOCKED")||state.equals("RECOVERING")||state.equals("CAPTURE_LOST")||state.equals("STARTING")))state="INACTIVE";
        if(state.equals("ACTIVE")&&(age<0||age>8000))state="STALE";
        boolean busy=NativeAppRoutingService.running();
        int heldRole=prefs.getInt("isolationRole",-1);
        long holdSeconds=Math.max(0,(prefs.getLong("isolationUntil",0)-android.os.SystemClock.elapsedRealtime()+999)/1000);
        headline.setText(state.equals("ACTIVE")?(heldRole>=0&&heldRole<3&&holdSeconds>0?"Connected · "+NativePeerProfiles.SLOTS[heldRole]+" held · "+holdSeconds+" s":"Connected"):state.equals("BLOCKED")?"Traffic blocked":state.equals("RECOVERING")?"Recovering · traffic held":state.equals("CAPTURE_LOST")?"Capture lost · protection unconfirmed":state.equals("STARTING")?"Connecting…":state.equals("STALE")?"Status stale":state.equals("FAILED")?"Connection refused":state.equals("INACTIVE")?"Service ended · protection unconfirmed":"Disconnected");
        if(underlayStatus!=null)underlayStatus.setText(busy?"Physical connection · "+prefs.getString("underlay","pending")+"\n"+prefs.getString("networkPreference","")+" · migrations "+prefs.getLong("networkMigrations",0)+"\nLast recovery: "+prefs.getString("lastRecoveryReason","none")+" · "+prefs.getLong("lastRecoveryMs",0)+" ms":"Physical connection · disconnected");
        speed.setText("↓ "+NativeRoutingMetrics.rate(state.equals("ACTIVE")?prefs.getLong("downRate",0):0)+"    ↑ "+NativeRoutingMetrics.rate(state.equals("ACTIVE")?prefs.getLong("upRate",0):0));
        blocked.setText("Blocked DNS · "+prefs.getLong("blocked",0));
        boolean active=state.equals("ACTIVE");
        if(dnsPending!=null){
            int provider=dnsProvider.getSelectedItemPosition(),mode=dnsMode.getSelectedItemPosition(),role=dnsRole.getSelectedItemPosition(),alternate=dnsAlternate.getSelectedItemPosition();
            if(NativeDnsTransportPolicy.supports(provider,mode)&&role>=0&&role<2&&alternate>=0&&alternate<2){
                String endpoint=(alternate==0?NativeProtectedDnsRelay.IPS:NativeProtectedDnsRelay.SECONDARY_IPS)[provider];
                int strategy=dnsStrategy.getSelectedItemPosition();
                String route=strategy==0?"Global "+NativePeerProfiles.SLOTS[role]:strategy==2?"Strict · unattributed blocked":"Follow · shared resolver "+NativePeerProfiles.SLOTS[role];
                String configured=NativeProtectedDnsRelay.NAMES[provider]+" · "+NativeDnsTransportPolicy.LABELS[mode]+" · "+route+" · "+endpoint;
                boolean pending=active&&(strategy!=prefs.getInt("dnsActiveStrategy",-1)||provider!=prefs.getInt("dnsActiveProvider",-1)||mode!=prefs.getInt("dnsActiveMode",-1)||role!=prefs.getInt("dnsActiveRole",-1)||alternate!=prefs.getInt("dnsActiveAlternate",-1));
                dnsPending.setText("Configured for next Start\n"+configured+(pending?"\nRestart required · active DNS unchanged":""));
            }else dnsPending.setText("Configured DNS · unsupported selection; Start will be refused");
        }
        if(dnsHealth!=null)dnsHealth.setText("Active DNS · "+(active?prefs.getString("dnsActiveConfig","")+"\nHealth: "+prefs.getString("dnsHealth","Waiting")+"\nTest: "+prefs.getString("dnsProbe","Not tested"):"Not active"));
        if(dnsTestButton!=null)dnsTestButton.setEnabled(busy&&state.equals("ACTIVE"));
        if(functionalTestButton!=null)functionalTestButton.setEnabled(busy&&active);
        if(functionalStatus!=null)functionalStatus.setText("Functional DNS test · "+(active?prefs.getString("dnsFunctional","Not tested"):"Not active"));
        int selected=0;for(AppRow r:apps)if(r.selected.isChecked())selected++;
        if(summary!=null)summary.setText("Configuration · "+(allApps.isChecked()?"All-app preview":selected+" apps selected")+" · "+(home.isChecked()?"2 exits + Home":"2 exits")+"\nChanges apply on next Start.");
        if(rootGuardStatus!=null)rootGuardStatus.setText("Root guard · "+(busy?prefs.getString("egressGuardStatus","Waiting for VPN") : NativeEgressGuard.staleStatus(this)));
        if(rootRecoverButton!=null)rootRecoverButton.setEnabled(!busy&&!rootRecoveryBusy&&NativeEgressGuard.pending(this));
        startButton.setEnabled(!busy&&!rootRecoveryBusy&&!NativeEgressGuard.pending(this));stopButton.setEnabled(busy);status.setText(formatActivity(report));
    }
    private static String formatActivity(String report){
        return report.replace("\nDNS provider=","\n\nDNS relay\nDNS provider=")
            .replace(" TLS opened=","\n\nTLS pool\nTLS opened=")
            .replace(" QUIC opened=","\n\nQUIC connections\nQUIC opened=")
            .replace(" DNS coalesced=","\n\nDNS latency\nDNS coalesced=")
            .replace(" QUIC fresh retries=","\n\nQUIC failures and retries\nQUIC fresh retries=")
            .replace(" QUIC socket tx=","\n\nQUIC packet evidence\nQUIC socket tx=")
            .replace(" DNS probe attempts=","\n\nDNS probe\nDNS probe attempts=")
            .replace("\nunderlay=","\n\nPhysical network\nunderlay=")
            .replace("\nDNS firewall drops=","\n\nProtection counters\nDNS firewall drops=")
            .replace("\nactive tuples=","\n\nFlow accounting\nactive tuples=");
    }
    private void pickHomeRoute(){
        try{
            SecureTunnelProfileStore.Profile profile=NativePeerProfiles.load(this)[2];
            if(profile==null){notice.setText("Import Home first.");showPage(0);return;}
            List<String> routes=NativeHomeRoutes.fromConfig(profile.configuration);
            if(routes.isEmpty()){new android.app.AlertDialog.Builder(this).setTitle("No private IPv4 route detected").setMessage("Enter a specific private CIDR covered by AllowedIPs. Broad Internet defaults are not suggested.").setPositiveButton("OK",null).show();return;}
            new android.app.AlertDialog.Builder(this).setTitle("Authorized Home routes").setItems(routes.toArray(new String[0]),(d,i)->{homeCidr.setText(routes.get(i));home.setChecked(true);}).setNegativeButton("Cancel",null).show();
        }catch(Exception e){new android.app.AlertDialog.Builder(this).setMessage("Home profile could not be read.").setPositiveButton("OK",null).show();}
    }
    private Spinner spinner(LinearLayout root,String[] options,int index){
        Spinner s=new Spinner(this);ArrayAdapter<String> a=new ArrayAdapter<>(this,android.R.layout.simple_spinner_item,options);
        a.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);s.setAdapter(a);s.setSelection(index>=0&&index<options.length?index:0);root.addView(s);return s;
    }
    private int value(Spinner spinner){return VALUES[spinner.getSelectedItemPosition()];}
    private void save(){
        android.content.SharedPreferences.Editor e=draft.edit().putBoolean("home",home.isChecked()).putString("homeCidr",homeCidr.getText().toString().trim()).putInt("default",fallback.getSelectedItemPosition());
        e.putInt("bootstrapOption",bootstrapOption.getSelectedItemPosition()).putBoolean("allApps",allApps.isChecked()).putBoolean("autoRecovery",autoRecovery.isChecked()).putInt("networkPreference",networkPreference.getSelectedItemPosition());
        e.putBoolean("rootEgressGuard",rootEgressGuard.isChecked()).putBoolean("rootLocalDiscovery",rootLocalDiscovery.isChecked());
        e.putInt("dnsStrategy",dnsStrategy.getSelectedItemPosition()).putInt("dnsMode",dnsMode.getSelectedItemPosition()).putInt("dnsProvider",dnsProvider.getSelectedItemPosition()).putInt("dnsRole",dnsRole.getSelectedItemPosition()).putInt("dnsAlternate",dnsAlternate.getSelectedItemPosition()).putBoolean("hostsEnabled",hostsEnabled.isChecked()).putBoolean("blockExternal853",blockExternal853.isChecked());
        for(int i=0;i<categories.length;i++)e.putInt("cat"+i,categories[i].getSelectedItemPosition());
        for(int i=0;i<protocols.length;i++)e.putInt("proto"+i,protocols[i].getSelectedItemPosition());
        for(AppRow r:apps)e.putBoolean("selected:"+r.pkg,r.selected.isChecked()).putInt("category:"+r.pkg,r.category.getSelectedItemPosition()).putInt("role:"+r.pkg,r.role.getSelectedItemPosition());
        for(int i=0;i<overrides.length;i++)e.putString("endpointOverride"+i,overrides[i].getText().toString().trim());
        e.apply();
    }
    private void autoSave(){if(draftReady)save();}
    private void wireDraftAutosave(){
        AdapterView.OnItemSelectedListener change=new AdapterView.OnItemSelectedListener(){
            public void onItemSelected(AdapterView<?> p,View v,int pos,long id){autoSave();}
            public void onNothingSelected(AdapterView<?> p){}
        };
        for(Spinner v:new Spinner[]{fallback,dnsProvider,dnsRole,dnsMode,dnsAlternate,networkPreference,bootstrapOption,dnsStrategy})v.setOnItemSelectedListener(change);
        for(Spinner v:categories)v.setOnItemSelectedListener(change);
        for(Spinner v:protocols)v.setOnItemSelectedListener(change);
        for(AppRow r:apps){r.category.setOnItemSelectedListener(change);r.role.setOnItemSelectedListener(change);}
        for(CheckBox v:new CheckBox[]{home,hostsEnabled,blockExternal853,autoRecovery,rootEgressGuard,rootLocalDiscovery})v.setOnCheckedChangeListener((b,on)->autoSave());
        android.text.TextWatcher edits=new android.text.TextWatcher(){
            public void beforeTextChanged(CharSequence s,int st,int c,int a){}
            public void onTextChanged(CharSequence s,int st,int b,int c){autoSave();}
            public void afterTextChanged(android.text.Editable e){}
        };
        homeCidr.addTextChangedListener(edits);
        for(EditText v:overrides)v.addTextChangedListener(edits);
        draftReady=true;
    }
    private static boolean indexedKey(String key,String prefix,int limit){
        if(!key.startsWith(prefix))return false;
        try{int i=Integer.parseInt(key.substring(prefix.length()));return i>=0&&i<limit&&key.equals(prefix+i);}catch(NumberFormatException e){return false;}
    }
    private static boolean appKey(String key,String prefix){return key.startsWith(prefix)&&AppUseCategories.validPackageName(key.substring(prefix.length()));}
    private static boolean routingKey(String k){
        return k.equals("dnsStrategy")||k.equals("dnsRole")||k.equals("default")||k.equals("allApps")||k.equals("home")||k.equals("homeCidr")
            ||indexedKey(k,"cat",AppUseCategories.LABELS.length)||indexedKey(k,"proto",NativeAppRoutingPolicy.SELECTORS.length)
            ||appKey(k,"selected:")||appKey(k,"category:")||appKey(k,"role:");
    }
    private static void putRoutingValue(android.content.SharedPreferences.Editor e,String k,Object v){
        if(!routingKey(k))throw new IllegalArgumentException("Unknown routing key");
        if(k.equals("allApps")||k.equals("home")||appKey(k,"selected:")){
            if(!(v instanceof Boolean))throw new IllegalArgumentException("Invalid boolean");
            e.putBoolean(k,(Boolean)v);return;
        }
        if(k.equals("homeCidr")){
            if(!(v instanceof String)||((String)v).length()>64)throw new IllegalArgumentException("Invalid Home CIDR");
            if(!((String)v).isEmpty())new NativeAppRoutingPolicy.Prefix((String)v);
            e.putString(k,(String)v);return;
        }
        int limit=k.equals("dnsStrategy")?3:(k.equals("default")||k.equals("dnsRole"))?2:appKey(k,"category:")?AppUseCategories.LABELS.length:CHOICES.length;
        if(!(v instanceof Integer)||(Integer)v<0||(Integer)v>=limit)throw new IllegalArgumentException("Invalid routing choice");
        e.putInt(k,(Integer)v);
    }
    private void exportRouting(android.net.Uri uri)throws Exception{
        org.json.JSONObject values=new org.json.JSONObject();
        for(Map.Entry<String,?> entry:draft.getAll().entrySet())if(routingKey(entry.getKey()))values.put(entry.getKey(),entry.getValue());
        byte[] bytes=new org.json.JSONObject().put("schema",1).put("routing",values).toString(2).getBytes(java.nio.charset.StandardCharsets.UTF_8);
        if(bytes.length>1048576)throw new java.io.IOException("Routing backup too large");
        try(java.io.OutputStream out=getContentResolver().openOutputStream(uri,"wt")){if(out==null)throw new java.io.IOException("No output");out.write(bytes);}
    }
    private void importRouting(android.net.Uri uri)throws Exception{
        byte[] bytes;
        try(InputStream in=getContentResolver().openInputStream(uri);java.io.ByteArrayOutputStream out=new java.io.ByteArrayOutputStream()){
            if(in==null)throw new java.io.IOException("No input");
            byte[] buf=new byte[8192];int n;
            while((n=in.read(buf))!=-1){if(out.size()+n>1048576)throw new java.io.IOException("Routing backup too large");out.write(buf,0,n);}
            bytes=out.toByteArray();
        }
        org.json.JSONObject root=new org.json.JSONObject(new String(bytes,java.nio.charset.StandardCharsets.UTF_8));
        if(root.length()!=2||!(root.get("schema") instanceof Integer)||root.getInt("schema")!=1)throw new IllegalArgumentException("Unsupported backup schema");
        org.json.JSONObject values=root.getJSONObject("routing");
        if(!values.has("default")||!values.has("allApps")||!values.has("home")||!values.has("homeCidr"))throw new IllegalArgumentException("Incomplete backup");
        if(values.getBoolean("home")&&values.getString("homeCidr").isEmpty())throw new IllegalArgumentException("Missing Home CIDR");
        android.content.SharedPreferences.Editor e=draft.edit();
        for(String key:draft.getAll().keySet())if(routingKey(key))e.remove(key);
        for(Iterator<String> it=values.keys();it.hasNext();){String k=it.next();putRoutingValue(e,k,values.get(k));}
        if(!e.commit())throw new java.io.IOException("Could not save routing backup");
        draftReady=false;recreate();
    }
    private Intent makeIntent()throws Exception{
        if(NativeEgressGuard.pending(this)&&!NativeAppRoutingService.running())throw new NativePeerProfiles.Rejected("EGRESS_JOURNAL_PENDING_RECOVER_OFFLINE");
        if(rootEgressGuard.isChecked()&&!allApps.isChecked())throw new NativePeerProfiles.Rejected("EGRESS_REQUIRES_ALL_APP_CAPTURE");
        if(!NativeDnsTransportPolicy.supports(dnsProvider.getSelectedItemPosition(),dnsMode.getSelectedItemPosition()))throw new IllegalArgumentException("unsupported DNS combination");
        boolean useHome=home.isChecked();String cidr=homeCidr.getText().toString().trim();
        int[] cat=new int[categories.length],proto=new int[protocols.length];String[] ips=new String[3];
        for(int i=0;i<cat.length;i++)cat[i]=value(categories[i]);
        for(int i=0;i<proto.length;i++)proto[i]=value(protocols[i]);
        for(int i=0;i<3;i++)ips[i]=overrides[i].getText().toString().trim();
        int def=fallback.getSelectedItemPosition();
        new NativeAppRoutingPolicy(useHome?new NativeAppRoutingPolicy.Prefix(cidr):null,def,cat,proto);
        List<AppRow> selected=new ArrayList<>();for(AppRow r:apps)if(allApps.isChecked()?(r.category.getSelectedItemPosition()!=r.suggested||value(r.role)!=NativeAppRoutingPolicy.INHERIT):r.selected.isChecked())selected.add(r);
        if(!allApps.isChecked()&&selected.isEmpty())throw new NativePeerProfiles.Rejected("SELECT_APPS_OR_ENABLE_ALL_APP_CAPTURE");
        if(selected.size()>512)throw new NativePeerProfiles.Rejected("TOO_MANY_EXPLICIT_APP_RULES");
        String[] names=new String[selected.size()];int[] appCat=new int[names.length],appRole=new int[names.length];
        for(int i=0;i<names.length;i++){AppRow r=selected.get(i);names[i]=r.pkg;appCat[i]=r.category.getSelectedItemPosition();appRole[i]=value(r.role);}
        if(!allApps.isChecked()){
            Set<String> included=new HashSet<>(Arrays.asList(names));
            for(int i=0;i<names.length;i++){
                int uid=getPackageManager().getApplicationInfo(names[i],0).uid;
                String[] shared=getPackageManager().getPackagesForUid(uid);
                if(uid<10000||shared==null||shared.length==0)throw new NativePeerProfiles.Rejected("SELECTED_UID_UNSUPPORTED_USE_ALL_APP_MODE");
                for(String member:shared){int j=Arrays.asList(names).indexOf(member);if(!included.contains(member)||j<0||appCat[j]!=appCat[i]||appRole[j]!=appRole[i])throw new NativePeerProfiles.Rejected("SHARED_UID_REQUIRES_ALL_MEMBERS_SAME_RULE_OR_ALL_APP_MODE");}
            }
        }
        String[] checked=NativePeerProfiles.prepare(this,useHome,ips,new String[3]);Arrays.fill(checked,null);
        return new Intent(this,NativeAppRoutingService.class).setAction(NativeAppRoutingService.START)
            .putExtra("home",useHome).putExtra("homeCidr",cidr).putExtra("default",def).putExtra("categories",cat).putExtra("protocols",proto)
            .putExtra("autoRecovery",autoRecovery.isChecked()).putExtra("networkPreference",networkPreference.getSelectedItemPosition()).putExtra("rootEgressGuard",rootEgressGuard.isChecked()).putExtra("rootLocalDiscovery",rootLocalDiscovery.isChecked()).putExtra("dnsStrategy",dnsStrategy.getSelectedItemPosition()).putExtra("dnsMode",dnsMode.getSelectedItemPosition()).putExtra("dnsProvider",dnsProvider.getSelectedItemPosition()).putExtra("dnsRole",dnsRole.getSelectedItemPosition()).putExtra("dnsAlternate",dnsAlternate.getSelectedItemPosition()).putExtra("hostsEnabled",hostsEnabled.isChecked()).putExtra("blockExternal853",blockExternal853.isChecked())
            .putExtra("bootstrapOption",bootstrapOption.getSelectedItemPosition()).putExtra("allApps",allApps.isChecked()).putExtra("apps",names).putExtra("appCategories",appCat).putExtra("appRoles",appRole).putExtra("overrides",ips);
    }
    private static String preflightReason(Exception e){return e instanceof NativePeerProfiles.Rejected?((NativePeerProfiles.Rejected)e).code:e instanceof IllegalArgumentException?"INVALID_HOME_CIDR_OR_ROUTING_OR_DNS_SELECTION":e.getClass().getSimpleName();}
    private void launch(){try{startForegroundService(makeIntent());notice.setText("Starting…");}catch(Exception e){notice.setText("Start refused: "+preflightReason(e));}}
    private void refresh(){
        try{
            SecureTunnelProfileStore.Profile[] p=NativePeerProfiles.load(this);StringBuilder s=new StringBuilder();
            for(int i=0;i<3;i++)s.append(NativePeerProfiles.SLOTS[i]).append(": ").append(p[i]==null?"missing":"encrypted profile saved").append('\n');
            profiles.setText(s.toString());
        }catch(Exception e){profiles.setText("Encrypted profile store unavailable");}
        final long generation=++hostsGeneration;
        new Thread(()->{
            String result;try{RootBlocklistStore.Snapshot snapshot=RootBlocklistStore.current(getFilesDir());result=snapshot==null?"No imported hosts list":snapshot.summary();}
            catch(Exception e){result="Hosts snapshot unavailable";}
            final String text=result;runOnUiThread(()->{if(generation==hostsGeneration&&!isDestroyed())hostsStatus.setText(text);});
        },"WonheeHostsSummary").start();
        updateLive();
    }
    @Override protected void onActivityResult(int request,int result,Intent data){
        super.onActivityResult(request,result,data);if(result!=RESULT_OK)return;
        if(request==VPN){launch();return;}
        if((request==EXPORT_RULES||request==IMPORT_RULES)&&data!=null&&data.getData()!=null){
            try{if(request==EXPORT_RULES){exportRouting(data.getData());notice.setText("Routing backup exported (no tunnel keys or DNS settings).");showPage(0);}else importRouting(data.getData());}
            catch(Exception e){notice.setText("Routing backup operation refused.");showPage(0);}return;
        }
        if(request==HOSTS&&data!=null&&data.getData()!=null){
            android.net.Uri uri=data.getData();hostsStatus.setText("Importing local list…");
            new Thread(()->{
                try(InputStream in=getContentResolver().openInputStream(uri)){RootBlocklistStore.importFrom(getFilesDir(),in);runOnUiThread(()->{hostsEnabled.setChecked(true);refresh();});}
                catch(Exception e){runOnUiThread(()->hostsStatus.setText("Import refused; prior valid list retained"));}
            },"WonheeHostsImport").start();return;
        }
        if(request>=IMPORT&&request<IMPORT+3&&data!=null&&data.getData()!=null){
            try(InputStream in=getContentResolver().openInputStream(data.getData())){
                NativePeerProfiles.save(this,request-IMPORT,in);refresh();if(request==IMPORT+2){try{List<String> routes=NativeHomeRoutes.fromConfig(NativePeerProfiles.load(this)[2].configuration);if(routes.size()==1)homeCidr.setText(routes.get(0));else if(!routes.isEmpty())pickHomeRoute();}catch(Exception ignored){}}
            }catch(NativePeerProfiles.Rejected e){notice.setText("Import refused: "+e.code);showPage(0);}
            catch(Exception|LinkageError e){notice.setText("Import refused");showPage(0);}
        }
    }
}
