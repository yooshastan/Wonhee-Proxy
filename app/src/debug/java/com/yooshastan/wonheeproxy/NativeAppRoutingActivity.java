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
    private static final int VPN=8300,IMPORT=8310,HOSTS=8320;
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
    private boolean readingHosts;
    private long hostsGeneration;
    private static final int BG=0xfff8f3ff, INK=0xff312446, ACCENT=0xff7051aa, SURFACE=0xffeee4fa, PINK=0xfff4ddec;
    private static final String[] SECTIONS={"Home","Tunnels","Routing","Protection","Activity"};
    private EditText homeCidr;
    private CheckBox home;
    private Spinner fallback,dnsProvider,dnsRole,networkPreference;
    private CheckBox hostsEnabled,blockExternal853,autoRecovery;
    private TextView hostsStatus;
    private android.content.SharedPreferences draft;
    private static final class AppRow {
        final String pkg;final CheckBox selected;final Spinner category,role;
        AppRow(String p,CheckBox s,Spinner c,Spinner r){pkg=p;selected=s;category=c;role=r;}
    }
    @Override public void onCreate(Bundle state){
        super.onCreate(state);
        draft=getSharedPreferences("native_app_route_draft_v1",MODE_PRIVATE);
        LinearLayout shell=new LinearLayout(this);shell.setOrientation(LinearLayout.VERTICAL);shell.setBackgroundColor(BG);
        shell.setFitsSystemWindows(true);
        LinearLayout header=new LinearLayout(this);header.setOrientation(LinearLayout.VERTICAL);header.setPadding(dp(18),dp(12),dp(18),dp(6));shell.addView(header);
        TextView brand=label(header,"wonhee  ✦",26);brand.setTypeface(null,android.graphics.Typeface.BOLD);
        label(header,"PROXY  /  0.20.1 PREVIEW",12);
        LinearLayout nav=new LinearLayout(this);nav.setOrientation(LinearLayout.HORIZONTAL);nav.setPadding(dp(6),0,dp(6),0);shell.addView(nav);
        for(int i=0;i<tabs.length;i++){
            final int at=i;Button t=new Button(this);t.setAllCaps(false);t.setText(SECTIONS[i]);t.setTextSize(11);t.setMinWidth(0);t.setMinimumWidth(0);t.setPadding(dp(2),0,dp(2),0);
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
            catch(Exception e){notice.setText("Start refused: choose 1–32 apps, valid profiles and Home CIDR.");}
        });startButton.setBackgroundTintList(android.content.res.ColorStateList.valueOf(ACCENT));startButton.setTextColor(0xffffffff);
        stopButton=button(root,"Stop connection",()->startService(new Intent(this,NativeAppRoutingService.class).setAction(NativeAppRoutingService.STOP)));
        notice=label(root,"",14);
        summary=label(root,"",15);
        button(root,"Tunnels · import or change",()->showPage(1));
        button(root,"Routing · choose apps and exits",()->showPage(2));
        button(root,"Protection · DNS and hosts",()->showPage(3));
        button(root,"Activity · connection details",()->showPage(4));
        label(root,"Selected apps only. Other apps use normal networking. Private DNS must remain OFF.",13);
        button(root,"Enable traffic notification",()->{if(android.os.Build.VERSION.SDK_INT>=33&&checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS)!=android.content.pm.PackageManager.PERMISSION_GRANTED)requestPermissions(new String[]{android.Manifest.permission.POST_NOTIFICATIONS},8330);else notice.setText("Notification permission already available.");});
        root=pages[1];
        label(root,"Tunnels",23);
        label(root,"Physical connection preference",15);
        networkPreference=spinner(root,NativeUnderlayPolicy.LABELS,draft.getInt("networkPreference",NativeUnderlayPolicy.WIFI_FIRST));
        label(root,"Wi-Fi or cellular preferences use the other validated physical network if needed. Android best available uses Android's best physical match where supported. Maintain current switches only on loss. Migration requires automatic recovery. Changes apply on next Start.",13);
        profiles=label(root,"",14);
        for(int i=0;i<3;i++){
            final int slot=i;
            button(root,"Import "+NativePeerProfiles.SLOTS[i],()->startActivityForResult(new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("*/*").addCategory(Intent.CATEGORY_OPENABLE),IMPORT+slot));
            EditText ip=new EditText(this);ip.setSingleLine(true);ip.setSaveEnabled(false);ip.setHint("Optional numeric override; blank = secure DNS");overrides[i]=ip;root.addView(ip);
        }
        home=new CheckBox(this);home.setText("Include Home private route");home.setChecked(draft.getBoolean("home",true));root.addView(home);
        homeCidr=new EditText(this);homeCidr.setSingleLine(true);homeCidr.setHint("Private Home IPv4 CIDR");homeCidr.setText(draft.getString("homeCidr","10.0.0.169/32"));root.addView(homeCidr);
        button(root,"Choose authorized Home route",this::pickHomeRoute);
        label(root,"Default Internet exit",15);fallback=spinner(root,new String[]{"Exit A","Exit B"},draft.getInt("default",0));
        button(root,"Save & return home",()->{save();showPage(0);});
        root=pages[3];
        label(root,"Protection",23);
        label(root,"DNS uses reusable authenticated TLS connections and a bounded positive DNS cache inside the chosen tunnel. UDP DNS only; TCP DNS fallback and application DoH interception are not supported. Captured IPv6 is blocked. Guard is in-process only.",14);
        autoRecovery=new CheckBox(this);autoRecovery.setText("Recover tunnels automatically while VPN remains established");autoRecovery.setChecked(draft.getBoolean("autoRecovery",true));root.addView(autoRecovery);
        label(root,"Recovery keeps selected apps inside the existing TUN. It uses the current session's endpoints and stops after five attempts. No protection guarantee if Android revokes or kills VPN.",13);
        label(root,"Authenticated DNS-over-TLS provider",14);
        dnsProvider=spinner(root,NativeProtectedDnsRelay.NAMES,draft.getInt("dnsProvider",0));
        label(root,"DNS tunnel (all captured system DNS)",14);
        dnsRole=spinner(root,new String[]{"Exit A","Exit B"},draft.getInt("dnsRole",0));
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
        label(root,"Categories",18);
        label(root,"Home destinations take precedence. Assign categories to Exit A or B, inherit default, or block public traffic.",14);
        for(int i=0;i<categories.length;i++){
            label(root,AppUseCategories.LABELS[i],14);categories[i]=spinner(root,CHOICES,draft.getInt("cat"+i,0));
        }
        label(root,"Protocol overrides",18);
        label(root,"These TCP/UDP destination-port rules override app and category exit assignments for public traffic; explicit app/category blocks still win. Port names are hints, not application-protocol detection.",14);
        for(int i=0;i<protocols.length;i++){
            label(root,NativeAppRoutingPolicy.SELECTOR_NAMES[i],14);protocols[i]=spinner(root,CHOICES,draft.getInt("proto"+i,0));
        }
        label(root,"Installed applications",18);
        label(root,"Select only apps you want to test. Choose a category and optional individual override. Changes apply at the next Start. Start with two browsers and Moka; do not select critical apps.",14);
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
            label(detail,"Category",13);Spinner category=spinner(detail,AppUseCategories.LABELS,draft.getInt("category:"+pkg,0));
            label(detail,"Individual exit override",13);Spinner role=spinner(detail,CHOICES,draft.getInt("role:"+pkg,0));
            appCard.addView(detail);detail.setVisibility(selected.isChecked()?View.VISIBLE:View.GONE);
            selected.setOnCheckedChangeListener((v,checked)->detail.setVisibility(checked?View.VISIBLE:View.GONE));
            apps.add(new AppRow(pkg,selected,category,role));
        }
        filter.addTextChangedListener(new android.text.TextWatcher(){
            public void beforeTextChanged(CharSequence x,int st,int c,int after){}
            public void onTextChanged(CharSequence x,int st,int before,int c){String q=x.toString().trim().toLowerCase(Locale.ROOT);for(Map.Entry<View,String> e:searchRows.entrySet())e.getKey().setVisibility(e.getValue().contains(q)?View.VISIBLE:View.GONE);}
            public void afterTextChanged(android.text.Editable x){}
        });
        button(root,"Save & return home",()->{save();notice.setText("Saved. Stop and Start to apply changes.");showPage(0);});
        root=pages[4];
        label(root,"Activity",23);
        status=label(root,"",14);
        button(root,"Copy redacted diagnostics",()->{
            android.content.ClipboardManager clipboard=(android.content.ClipboardManager)getSystemService(CLIPBOARD_SERVICE);
            if(clipboard!=null)clipboard.setPrimaryClip(ClipData.newPlainText("Wonhee diagnostics",status.getText()));
        });
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
        setContentView(shell);showPage(0);refresh();
    }
    private int dp(int n){return (int)(n*getResources().getDisplayMetrics().density+0.5f);}
    private android.graphics.drawable.GradientDrawable round(int color,int radius){android.graphics.drawable.GradientDrawable d=new android.graphics.drawable.GradientDrawable();d.setColor(color);d.setCornerRadius(dp(radius));return d;}
    private TextView label(LinearLayout root,String value,int size){TextView v=new TextView(this);v.setText(value);v.setTextColor(INK);v.setTextSize(size);v.setPadding(0,dp(5),0,dp(5));root.addView(v);return v;}
    private Button button(LinearLayout root,String value,Runnable action){Button b=new Button(this);b.setAllCaps(false);b.setText(value);b.setTextColor(INK);b.setBackgroundTintList(android.content.res.ColorStateList.valueOf(SURFACE));b.setOnClickListener(v->action.run());root.addView(b);return b;}
    private void showPage(int next){page=next;for(int i=0;i<pages.length;i++){pages[i].setVisibility(i==next?View.VISIBLE:View.GONE);tabs[i].setBackgroundTintList(android.content.res.ColorStateList.valueOf(i==next?ACCENT:SURFACE));tabs[i].setTextColor(i==next?0xffffffff:INK);}scroll.scrollTo(0,0);updateLive();}
    @Override protected void onResume(){super.onResume();ui.removeCallbacks(tick);ui.post(tick);}
    @Override protected void onPause(){ui.removeCallbacks(tick);super.onPause();}
    @Override public void onBackPressed(){if(page!=0)showPage(0);else super.onBackPressed();}
    private void updateLive(){
        if(headline==null||status==null)return;
        android.content.SharedPreferences prefs=getSharedPreferences(NativeAppRoutingService.PREFS,MODE_PRIVATE);
        String state=prefs.getString("state","IDLE"),report=prefs.getString("status","Not started");
        long age=android.os.SystemClock.elapsedRealtime()-prefs.getLong("heartbeat",0);
        if(!NativeAppRoutingService.running()&&(state.equals("ACTIVE")||state.equals("BLOCKED")||state.equals("RECOVERING")||state.equals("CAPTURE_LOST")||state.equals("STARTING")))state="INACTIVE";
        if(state.equals("ACTIVE")&&(age<0||age>8000))state="STALE";
        boolean busy=NativeAppRoutingService.running();
        headline.setText(state.equals("ACTIVE")?"Connected":state.equals("BLOCKED")?"Traffic blocked":state.equals("RECOVERING")?"Recovering · traffic held":state.equals("CAPTURE_LOST")?"Capture lost · protection unconfirmed":state.equals("STARTING")?"Connecting…":state.equals("STALE")?"Status stale":state.equals("FAILED")?"Connection refused":"Disconnected");
        if(underlayStatus!=null)underlayStatus.setText(busy?"Physical connection · "+prefs.getString("underlay","pending")+"\n"+prefs.getString("networkPreference","")+" · migrations "+prefs.getLong("networkMigrations",0)+"\nLast recovery: "+prefs.getString("lastRecoveryReason","none")+" · "+prefs.getLong("lastRecoveryMs",0)+" ms":"Physical connection · disconnected");
        speed.setText("↓ "+NativeRoutingMetrics.rate(state.equals("ACTIVE")?prefs.getLong("downRate",0):0)+"    ↑ "+NativeRoutingMetrics.rate(state.equals("ACTIVE")?prefs.getLong("upRate",0):0));
        blocked.setText("Blocked DNS · "+prefs.getLong("blocked",0));
        int selected=0;for(AppRow r:apps)if(r.selected.isChecked())selected++;
        if(summary!=null)summary.setText("Configuration · "+selected+" apps selected · "+(home.isChecked()?"2 exits + Home":"2 exits")+"\nChanges apply on next Start.");
        startButton.setEnabled(!busy);stopButton.setEnabled(busy);status.setText(report);
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
        e.putBoolean("autoRecovery",autoRecovery.isChecked()).putInt("networkPreference",networkPreference.getSelectedItemPosition());
        e.putInt("dnsProvider",dnsProvider.getSelectedItemPosition()).putInt("dnsRole",dnsRole.getSelectedItemPosition()).putBoolean("hostsEnabled",hostsEnabled.isChecked()).putBoolean("blockExternal853",blockExternal853.isChecked());
        for(int i=0;i<categories.length;i++)e.putInt("cat"+i,categories[i].getSelectedItemPosition());
        for(int i=0;i<protocols.length;i++)e.putInt("proto"+i,protocols[i].getSelectedItemPosition());
        for(AppRow r:apps)e.putBoolean("selected:"+r.pkg,r.selected.isChecked()).putInt("category:"+r.pkg,r.category.getSelectedItemPosition()).putInt("role:"+r.pkg,r.role.getSelectedItemPosition());
        e.apply();
    }
    private Intent makeIntent()throws Exception{
        boolean useHome=home.isChecked();String cidr=homeCidr.getText().toString().trim();
        int[] cat=new int[categories.length],proto=new int[protocols.length];String[] ips=new String[3];
        for(int i=0;i<cat.length;i++)cat[i]=value(categories[i]);
        for(int i=0;i<proto.length;i++)proto[i]=value(protocols[i]);
        for(int i=0;i<3;i++)ips[i]=overrides[i].getText().toString().trim();
        int def=fallback.getSelectedItemPosition();
        new NativeAppRoutingPolicy(useHome?new NativeAppRoutingPolicy.Prefix(cidr):null,def,cat,proto);
        List<AppRow> selected=new ArrayList<>();for(AppRow r:apps)if(r.selected.isChecked())selected.add(r);
        if(selected.isEmpty()||selected.size()>32)throw new IllegalArgumentException();
        String[] names=new String[selected.size()];int[] appCat=new int[names.length],appRole=new int[names.length];
        for(int i=0;i<names.length;i++){AppRow r=selected.get(i);names[i]=r.pkg;appCat[i]=r.category.getSelectedItemPosition();appRole[i]=value(r.role);}
        String[] checked=NativePeerProfiles.prepare(this,useHome,ips,new String[3]);Arrays.fill(checked,null);
        return new Intent(this,NativeAppRoutingService.class).setAction(NativeAppRoutingService.START)
            .putExtra("home",useHome).putExtra("homeCidr",cidr).putExtra("default",def).putExtra("categories",cat).putExtra("protocols",proto)
            .putExtra("autoRecovery",autoRecovery.isChecked()).putExtra("networkPreference",networkPreference.getSelectedItemPosition()).putExtra("dnsProvider",dnsProvider.getSelectedItemPosition()).putExtra("dnsRole",dnsRole.getSelectedItemPosition()).putExtra("hostsEnabled",hostsEnabled.isChecked()).putExtra("blockExternal853",blockExternal853.isChecked())
            .putExtra("apps",names).putExtra("appCategories",appCat).putExtra("appRoles",appRole).putExtra("overrides",ips);
    }
    private void launch(){try{startForegroundService(makeIntent());notice.setText("Starting…");;}catch(Exception e){notice.setText("Start refused: "+e.getClass().getSimpleName());}}
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
