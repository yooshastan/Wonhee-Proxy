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
    private TextView status,profiles;
    private EditText homeCidr;
    private CheckBox home;
    private Spinner fallback,dnsProvider,dnsRole;
    private CheckBox hostsEnabled,blockExternal853;
    private TextView hostsStatus;
    private android.content.SharedPreferences draft;
    private static final class AppRow {
        final String pkg;final CheckBox selected;final Spinner category,role;
        AppRow(String p,CheckBox s,Spinner c,Spinner r){pkg=p;selected=s;category=c;role=r;}
    }
    @Override public void onCreate(Bundle state){
        super.onCreate(state);
        draft=getSharedPreferences("native_app_route_draft_v1",MODE_PRIVATE);
        LinearLayout root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);
        int pad=(int)(16*getResources().getDisplayMetrics().density);root.setPadding(pad,pad,pad,pad);
        label(root,"Wonhee 0.17.1 · Protected app routing",22);
        label(root,"Experimental rootless VPN. Only checked apps are captured; other apps use normal networking. IPv4 TCP/UDP only; IPv6 and unsupported traffic blocked inside the VPN. Private DNS must remain OFF. System UDP DNS is relayed over authenticated TLS inside a selected tunnel; direct port 53 is blocked. TCP DNS fallback is not supported yet. Application DoH over port 443 is not identifiable. No protection before startup or after Stop.",14);
        button(root,"Start selected-app routing",()->{
            try{makeIntent();save();Intent consent=VpnService.prepare(this);if(consent!=null)startActivityForResult(consent,VPN);else launch();}
            catch(Exception e){status.setText("Check configuration: select 1–32 apps, valid Home CIDR and profiles.");}
        });
        button(root,"Stop (normal networking resumes)",()->startService(new Intent(this,NativeAppRoutingService.class).setAction(NativeAppRoutingService.STOP)));
        status=label(root,"",15);button(root,"Refresh status",this::refresh);
        button(root,"Simulate tunnel failure (test guard)",()->startService(new Intent(this,NativeAppRoutingService.class).setAction(NativeAppRoutingService.GUARD_TEST)));
        label(root,"1 · Tunnels",18);profiles=label(root,"",14);
        for(int i=0;i<3;i++){
            final int slot=i;
            button(root,"Import "+NativePeerProfiles.SLOTS[i],()->startActivityForResult(new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("*/*").addCategory(Intent.CATEGORY_OPENABLE),IMPORT+slot));
            EditText ip=new EditText(this);ip.setSingleLine(true);ip.setSaveEnabled(false);ip.setHint("Optional numeric override; blank = secure DNS");overrides[i]=ip;root.addView(ip);
        }
        home=new CheckBox(this);home.setText("Include Home private route");home.setChecked(draft.getBoolean("home",true));root.addView(home);
        homeCidr=new EditText(this);homeCidr.setSingleLine(true);homeCidr.setHint("Private Home IPv4 CIDR");homeCidr.setText(draft.getString("homeCidr","10.0.0.169/32"));root.addView(homeCidr);
        label(root,"Default Internet exit",15);fallback=spinner(root,new String[]{"Exit A","Exit B"},draft.getInt("default",0));
        label(root,"2 · Network protection",18);
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
        label(root,"3 · Category routing",18);
        label(root,"Home destinations take precedence. Assign categories to Exit A or B, inherit default, or block public traffic.",14);
        for(int i=0;i<categories.length;i++){
            label(root,AppUseCategories.LABELS[i],14);categories[i]=spinner(root,CHOICES,draft.getInt("cat"+i,0));
        }
        label(root,"4 · Protocol overrides",18);
        label(root,"These TCP/UDP destination-port rules override app and category exit assignments for public traffic; explicit app/category blocks still win. Port names are hints, not application-protocol detection.",14);
        for(int i=0;i<protocols.length;i++){
            label(root,NativeAppRoutingPolicy.SELECTOR_NAMES[i],14);protocols[i]=spinner(root,CHOICES,draft.getInt("proto"+i,0));
        }
        label(root,"5 · Select installed apps",18);
        label(root,"Select only apps you want to test. Choose a category and optional individual override. Changes apply at the next Start. Start with two browsers and Moka; do not select critical apps.",14);
        List<ResolveInfo> visible=getPackageManager().queryIntentActivities(new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER),0);
        visible.sort(Comparator.comparing(r->r.loadLabel(getPackageManager()).toString(),String.CASE_INSENSITIVE_ORDER));
        Set<String> seen=new HashSet<>();
        for(ResolveInfo r:visible){
            if(r.activityInfo==null)continue;String pkg=r.activityInfo.packageName;
            if(pkg.equals(getPackageName())||!AppUseCategories.validPackageName(pkg)||!seen.add(pkg))continue;
            CheckBox selected=new CheckBox(this);selected.setText(r.loadLabel(getPackageManager())+" ("+pkg+")");
            selected.setChecked(draft.getBoolean("selected:"+pkg,false));root.addView(selected);
            LinearLayout detail=new LinearLayout(this);detail.setOrientation(LinearLayout.VERTICAL);
            label(detail,"Category",13);Spinner category=spinner(detail,AppUseCategories.LABELS,draft.getInt("category:"+pkg,0));
            label(detail,"Individual exit override",13);Spinner role=spinner(detail,CHOICES,draft.getInt("role:"+pkg,0));
            root.addView(detail);detail.setVisibility(selected.isChecked()?View.VISIBLE:View.GONE);
            selected.setOnCheckedChangeListener((v,checked)->detail.setVisibility(checked?View.VISIBLE:View.GONE));
            apps.add(new AppRow(pkg,selected,category,role));
        }
        button(root,"Save routing choices",()->{save();status.setText("Saved locally. Stop and Start to apply changes.");});
        button(root,"Advanced diagnostics",()->new android.app.AlertDialog.Builder(this)
            .setTitle("Advanced diagnostics — stop VPN first")
            .setItems(new String[]{"Native transfer regression","Read-only readiness","Legacy kernel lab / Safe Stop"},(dialog,index)->{
                Class<?> target=index==0?RootlessNativePeerActivity.class:index==1?RootlabReadinessActivity.class:RootlabTwoPeerActivity.class;
                if(index==2)new android.app.AlertDialog.Builder(this).setTitle("Legacy kernel laboratory").setMessage("This is not the current connection screen. Use only for deliberate diagnostics or exact-owned Safe Stop of old root links. Do not start it while protected routing is active.").setPositiveButton("Open legacy lab",(d,b)->startActivity(new Intent(this,target))).setNegativeButton("Cancel",null).show();
                else startActivity(new Intent(this,target));
            }).setNegativeButton("Cancel",null).show());
        ScrollView scroll=new ScrollView(this);scroll.setFillViewport(true);scroll.addView(root);scroll.setFitsSystemWindows(true);setContentView(scroll);refresh();
    }
    private TextView label(LinearLayout root,String value,int size){TextView v=new TextView(this);v.setText(value);v.setTextSize(size);root.addView(v);return v;}
    private void button(LinearLayout root,String value,Runnable action){Button b=new Button(this);b.setText(value);b.setOnClickListener(v->action.run());root.addView(b);}
    private Spinner spinner(LinearLayout root,String[] options,int index){
        Spinner s=new Spinner(this);ArrayAdapter<String> a=new ArrayAdapter<>(this,android.R.layout.simple_spinner_item,options);
        a.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);s.setAdapter(a);s.setSelection(index>=0&&index<options.length?index:0);root.addView(s);return s;
    }
    private int value(Spinner spinner){return VALUES[spinner.getSelectedItemPosition()];}
    private void save(){
        android.content.SharedPreferences.Editor e=draft.edit().putBoolean("home",home.isChecked()).putString("homeCidr",homeCidr.getText().toString().trim()).putInt("default",fallback.getSelectedItemPosition());
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
            .putExtra("dnsProvider",dnsProvider.getSelectedItemPosition()).putExtra("dnsRole",dnsRole.getSelectedItemPosition()).putExtra("hostsEnabled",hostsEnabled.isChecked()).putExtra("blockExternal853",blockExternal853.isChecked())
            .putExtra("apps",names).putExtra("appCategories",appCat).putExtra("appRoles",appRole).putExtra("overrides",ips);
    }
    private void launch(){try{startForegroundService(makeIntent());status.setText("Starting — refresh status shortly");}catch(Exception e){status.setText("Start refused: "+e.getClass().getSimpleName());}}
    private void refresh(){
        try{
            SecureTunnelProfileStore.Profile[] p=NativePeerProfiles.load(this);StringBuilder s=new StringBuilder();
            for(int i=0;i<3;i++)s.append(NativePeerProfiles.SLOTS[i]).append(": ").append(p[i]==null?"missing":"encrypted profile saved").append('\n');
            profiles.setText(s.toString());
        }catch(Exception e){profiles.setText("Encrypted profile store unavailable");}
        try{RootBlocklistStore.Snapshot snapshot=RootBlocklistStore.current(getFilesDir());hostsStatus.setText(snapshot==null?"No imported hosts list":snapshot.summary());}
        catch(Exception e){hostsStatus.setText("Hosts snapshot unavailable");}
        status.setText(getSharedPreferences(NativeAppRoutingService.PREFS,MODE_PRIVATE).getString("status","Not started"));
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
                NativePeerProfiles.save(this,request-IMPORT,in);refresh();
            }catch(NativePeerProfiles.Rejected e){status.setText("Import refused: "+e.code);}
            catch(Exception|LinkageError e){status.setText("Import refused");}
        }
    }
}
