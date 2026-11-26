package com.yooshastan.wonheeproxy;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.view.WindowInsets;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.io.InputStream;

public final class RootlessNativePeerActivity extends Activity {
    private static final int IMPORT=8200, VPN=8210;
    private TextView slots,status;
    private CheckBox home;
    private EditText homeTarget,homePort;
    private boolean requestedHome;
    private final EditText[] overrides=new EditText[3];
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        if(state!=null) requestedHome=state.getBoolean("requestedHome");
        LinearLayout root=new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad=(int)(16*getResources().getDisplayMetrics().density);
        root.setPadding(pad,pad,pad,pad);
        TextView title=new TextView(this);
        title.setText("Wonhee 0.15.89 · Scoped TCP + UDP lab");
        title.setTextSize(22);root.addView(title);
        TextView info=new TextView(this);
        info.setText("Import two independent exit profiles and optionally Home. Profiles stay encrypted locally. Hostname profiles can be saved without DNS. For a hostname endpoint, enter its provider-confirmed numeric IP in the corresponding optional override box. Original port and encrypted configuration stay unchanged. Two concurrent flows per peer through one package-scoped TUN. Exits use certificate-verified HTTPS; optional Home uses a credential-free HTTP GET /. Response headers and declared body samples are bounded. Five fixed UDP DNS requests per Internet exit test datagrams through the same tunnel; no system DNS changes. No redirects, DNS changes or default route. Stop earlier tests and root tunnels using Exact-owned Safe Stop, disconnect other VPNs, and keep Private DNS OFF.");
        root.addView(info);
        slots=new TextView(this);root.addView(slots);
        for(int i=0;i<3;i++) {
            final int slot=i;
            Button b=new Button(this);b.setText("Import "+NativePeerProfiles.SLOTS[i]);
            b.setOnClickListener(v->pick(slot));root.addView(b);
            EditText ip=new EditText(this);
            ip.setSingleLine(true);
            ip.setSaveEnabled(false);
            ip.setHint("Numeric IP override for hostname only");
            overrides[i]=ip;root.addView(ip);
        }
        home=new CheckBox(this);home.setText("Include Home (third peer)");home.setChecked(true);root.addView(home);
        homeTarget=new EditText(this);homeTarget.setSingleLine(true);homeTarget.setHint("Private Home service IPv4");root.addView(homeTarget);
        homePort=new EditText(this);homePort.setSingleLine(true);homePort.setHint("Home TCP port");homePort.setText("4533");root.addView(homePort);
        status=new TextView(this);status.setPadding(0,pad,0,pad);root.addView(status);
        Button check=new Button(this);check.setText("Check selected profiles (no network)");
        check.setOnClickListener(v->checkProfiles());root.addView(check);
        Button start=new Button(this);start.setText("Start scoped TCP + UDP test (120 seconds)");
        start.setOnClickListener(v->{
            if(!checkProfiles()) return;
            requestedHome=home.isChecked();
            Intent permission=VpnService.prepare(this);
            if(permission!=null) startActivityForResult(permission,VPN);else launch();
        });root.addView(start);
        Button stop=new Button(this);stop.setText("Stop and release all peers");
        stop.setOnClickListener(v->startService(new Intent(this,RootlessNativePeerService.class).setAction(RootlessNativePeerService.STOP)));root.addView(stop);
        Button refresh=new Button(this);refresh.setText("Refresh status");refresh.setOnClickListener(v->refresh());root.addView(refresh);
        ScrollView scroll=new ScrollView(this);scroll.setFillViewport(true);scroll.addView(root);
        scroll.setOnApplyWindowInsetsListener((v,insets)->{
            int bottom=Build.VERSION.SDK_INT>=30?insets.getInsets(WindowInsets.Type.systemBars()).bottom:insets.getSystemWindowInsetBottom();
            v.setPadding(0,0,0,bottom);return insets;
        });setContentView(scroll);refresh();
    }
    @Override protected void onSaveInstanceState(Bundle out){super.onSaveInstanceState(out);out.putBoolean("requestedHome",requestedHome);}
    private void pick(int slot) {
        Intent i=new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("*/*").addCategory(Intent.CATEGORY_OPENABLE);
        startActivityForResult(i,IMPORT+slot);
    }
    private String[] endpointOverrides() {
        String[] values=new String[3];
        for(int i=0;i<3;i++) values[i]=overrides[i].getText().toString().trim();
        return values;
    }
    private void launch() {
        Intent i=new Intent(this,RootlessNativePeerService.class).setAction(RootlessNativePeerService.START).putExtra("home",requestedHome).putExtra("overrides",endpointOverrides()).putExtra("target",homeTarget.getText().toString().trim()).putExtra("port",homePort.getText().toString().trim());
        startForegroundService(i);status.setText("Starting peer validation…");
    }
    @Override protected void onActivityResult(int request,int result,Intent data) {
        super.onActivityResult(request,result,data);
        if(result!=RESULT_OK) return;
        if(request==VPN){launch();return;}
        if(request>=IMPORT && request<IMPORT+3 && data!=null && data.getData()!=null) {
            try(InputStream in=getContentResolver().openInputStream(data.getData())) {
                NativePeerProfiles.save(this,request-IMPORT,in);refresh();
                status.setText("Encrypted import accepted. Press Start to test all selected peers.");
            } catch(NativePeerProfiles.Rejected rejected) {
                status.setText("Import refused: "+rejected.code+". Previous stored profile retained.");
            } catch(Exception|LinkageError rejected) {status.setText("Import refused: file unavailable or native bridge error. Previous stored profile retained.");}
        }
    }
    private boolean checkProfiles() {
        try {
            if(home.isChecked()) RootlessNativePeerService.validateHome(homeTarget.getText().toString().trim(),homePort.getText().toString().trim());
            String[] validated=NativePeerProfiles.prepare(this,home.isChecked(),endpointOverrides(),new String[3]);
            java.util.Arrays.fill(validated,null);
            status.setText("PROFILE CHECK PASSED — selected profiles present and distinct. No network started.");
            return true;
        } catch(NativePeerProfiles.Rejected rejected) {
            status.setText("PROFILE CHECK FAILED — "+rejected.code);
        } catch(IllegalArgumentException rejected) {
            status.setText("PROFILE CHECK FAILED — enter a private Home IPv4 and valid TCP port.");
        } catch(Exception|LinkageError rejected) {status.setText("PROFILE CHECK FAILED — internal validation unavailable.");}
        return false;
    }
    private void refresh() {
        try {
            SecureTunnelProfileStore.Profile[] p=NativePeerProfiles.load(this);
            StringBuilder s=new StringBuilder();
            for(int i=0;i<3;i++) s.append(NativePeerProfiles.SLOTS[i]).append(": ").append(p[i]==null?"missing":"encrypted profile saved").append('\n');
            slots.setText(s.toString());
        } catch(Exception failure){slots.setText("Encrypted profile store unavailable.");}
        status.setText(getSharedPreferences(RootlessNativePeerService.PREFS,MODE_PRIVATE).getString("status","No live peer test run."));
    }
}
