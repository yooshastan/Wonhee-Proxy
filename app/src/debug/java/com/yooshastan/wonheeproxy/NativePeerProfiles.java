package com.yooshastan.wonheeproxy;

import android.content.Context;
import com.wireguard.config.Config;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

final class NativePeerProfiles {
    static final String[] SLOTS={"Exit A","Exit B","Home"};
    static final String[] IDS={"exit-a","exit-b","home"};
    static final int LIMIT=32768;
    private NativePeerProfiles() {}
    static Config parse(InputStream stream) throws Exception {
        if(stream==null) throw new IllegalArgumentException();
        ByteArrayOutputStream out=new ByteArrayOutputStream();
        byte[] buffer=new byte[4096];
        byte[] data=null;
        try {
            int n;
            while((n=stream.read(buffer))!=-1) {
                if(out.size()+n>LIMIT) throw new IllegalArgumentException();
                out.write(buffer,0,n);
            }
            data=out.toByteArray();
            return Config.parse(new ByteArrayInputStream(data));
        } finally { Arrays.fill(buffer,(byte)0); if(data!=null) Arrays.fill(data,(byte)0); }
    }
    static String canonical(Config c) {
        String stripped=RootIsolatedWireGuardSetconfCodec.stripCanonicalQuick(c.toWgQuickString());
        if(!RootlessNativeBridge.validatePeerProfile(stripped)) throw new IllegalArgumentException();
        return stripped;
    }
    static void save(Context context,int slot,InputStream stream) throws Exception {
        Config c=parse(stream);
        canonical(c);
        new SecureTunnelProfileStore(context).save(new SecureTunnelProfileStore.Profile(SLOTS[slot],c.toWgQuickString()));
    }
    static SecureTunnelProfileStore.Profile[] load(Context context) throws Exception {
        SecureTunnelProfileStore.Profile[] slots=new SecureTunnelProfileStore.Profile[3];
        for(SecureTunnelProfileStore.Profile p:new SecureTunnelProfileStore(context).load())
            for(int i=0;i<3;i++) if(SLOTS[i].equals(p.name)) slots[i]=p;
        return slots;
    }
    static String[] prepare(Context context,boolean home) throws Exception {
        SecureTunnelProfileStore.Profile[] slots=load(context);
        int count=home?3:2;
        String[] configs=new String[count];
        Set<String> pairs=new HashSet<>();
        for(int i=0;i<count;i++) {
            if(slots[i]==null) throw new IllegalArgumentException();
            byte[] data=slots[i].configuration.getBytes(StandardCharsets.UTF_8);
            Config c;
            try {c=parse(new ByteArrayInputStream(data));} finally {Arrays.fill(data,(byte)0);}
            configs[i]=canonical(c);
            String pair=c.getInterface().getKeyPair().getPublicKey().toBase64()+":"
                    +c.getPeers().get(0).getPublicKey().toBase64();
            if(!pairs.add(pair)) throw new IllegalArgumentException();
        }
        return configs;
    }
}
