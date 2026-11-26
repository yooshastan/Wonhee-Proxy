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
    // Only fixed reason codes and slot labels may cross the diagnostic boundary.
    static final class Rejected extends IllegalArgumentException {
        final String code;
        Rejected(String code) { super(code); this.code=code; }
    }
    private static Rejected reject(int slot,String reason) {
        return new Rejected(IDS[slot]+"/"+reason);
    }
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
        Config c;
        try { c=parse(stream); }
        catch(Exception failure) { throw reject(slot,"PARSE_OR_SIZE_REJECTED"); }
        checkedCanonical(c,slot);
        try { new SecureTunnelProfileStore(context).save(new SecureTunnelProfileStore.Profile(SLOTS[slot],c.toWgQuickString())); }
        catch(Exception failure) { throw reject(slot,"ENCRYPTED_SAVE_FAILED"); }
    }
    static SecureTunnelProfileStore.Profile[] load(Context context) throws Exception {
        SecureTunnelProfileStore.Profile[] slots=new SecureTunnelProfileStore.Profile[3];
        for(SecureTunnelProfileStore.Profile p:new SecureTunnelProfileStore(context).load())
            for(int i=0;i<3;i++) if(SLOTS[i].equals(p.name)) slots[i]=p;
        return slots;
    }
    private static String checkedCanonical(Config c,int slot) {
        if(c.getPeers().size()!=1) throw reject(slot,"REQUIRES_ONE_PEER");
        String stripped;
        try { stripped=RootIsolatedWireGuardSetconfCodec.stripCanonicalQuick(c.toWgQuickString()); }
        catch(IllegalArgumentException failure) { throw reject(slot,"CANONICAL_FIELDS_REJECTED"); }
        if(!RootlessNativeBridge.available()) throw reject(slot,"NATIVE_LIBRARY_UNAVAILABLE");
        if(!RootlessNativeBridge.validatePeerProfile(stripped)) throw reject(slot,"NATIVE_PROFILE_REJECTED");
        return stripped;
    }
    static String[] prepare(Context context,boolean home) throws Exception {
        SecureTunnelProfileStore.Profile[] slots;
        try { slots=load(context); }
        catch(Exception failure) { throw new Rejected("ENCRYPTED_STORE_UNAVAILABLE"); }
        int count=home?3:2;
        String[] configs=new String[count];
        java.util.Map<String,Integer> pairs=new java.util.HashMap<>();
        for(int i=0;i<count;i++) {
            if(slots[i]==null) throw reject(i,"PROFILE_MISSING");
            byte[] data=slots[i].configuration.getBytes(StandardCharsets.UTF_8);
            Config c;
            try { c=parse(new ByteArrayInputStream(data)); }
            catch(Exception failure) { throw reject(i,"STORED_PROFILE_PARSE_REJECTED"); }
            finally {Arrays.fill(data,(byte)0);}
            configs[i]=checkedCanonical(c,i);
            String pair=c.getInterface().getKeyPair().getPublicKey().toBase64()+":"
                    +c.getPeers().get(0).getPublicKey().toBase64();
            Integer prior=pairs.putIfAbsent(pair,i);
            if(prior!=null) throw reject(i,"DUPLICATE_PEER_IDENTITY_WITH_"+IDS[prior]);
        }
        return configs;
    }
}
