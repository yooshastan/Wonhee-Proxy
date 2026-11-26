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
    static void save(Context context,int slot,InputStream stream) throws Exception {
        Config c;
        try { c=parse(stream); }
        catch(Exception failure) { throw reject(slot,"PARSE_OR_SIZE_REJECTED"); }
        checkedCanonical(c,slot,true);
        try { new SecureTunnelProfileStore(context).save(new SecureTunnelProfileStore.Profile(SLOTS[slot],c.toWgQuickString())); }
        catch(Exception failure) { throw reject(slot,"ENCRYPTED_SAVE_FAILED"); }
    }
    static SecureTunnelProfileStore.Profile[] load(Context context) throws Exception {
        SecureTunnelProfileStore.Profile[] slots=new SecureTunnelProfileStore.Profile[3];
        for(SecureTunnelProfileStore.Profile p:new SecureTunnelProfileStore(context).load())
            for(int i=0;i<3;i++) if(SLOTS[i].equals(p.name)) slots[i]=p;
        return slots;
    }
    private static String checkedCanonical(Config c,int slot,boolean allowHostname) {
        if(c.getPeers().size()!=1) throw reject(slot,"REQUIRES_ONE_PEER");
        String stripped;
        try { stripped=RootIsolatedWireGuardSetconfCodec.stripCanonicalQuick(c.toWgQuickString()); }
        catch(IllegalArgumentException failure) { throw reject(slot,"CANONICAL_FIELDS_REJECTED"); }
        if(!RootlessNativeBridge.available()) throw reject(slot,"NATIVE_LIBRARY_UNAVAILABLE");
        int code=RootlessNativeBridge.validatePeerProfile(stripped);
        if(code!=1 && !(allowHostname && code==9)) throw reject(slot,nativeReason(code));
        return stripped;
    }
    static String nativeReason(int code) {
        switch(code) {
            case 2: return "NATIVE_FORMAT_REJECTED";
            case 3: return "PRIVATE_KEY_FORMAT_REJECTED";
            case 4: return "PUBLIC_KEY_FORMAT_REJECTED";
            case 5: return "SELF_PEER_IDENTITY_REJECTED";
            case 6: return "ALLOWED_IPS_REJECTED";
            case 7: return "PORT_OR_KEEPALIVE_REJECTED";
            case 8: return "PRESHARED_KEY_FORMAT_REJECTED";
            case 9: return "HOSTNAME_REQUIRES_NUMERIC_IP";
            case 10: return "ENDPOINT_ADDRESS_OR_PORT_REJECTED";
            default: return "NATIVE_PROFILE_REJECTED";
        }
    }
    // Explicit, temporary numeric override applies only to hostname endpoints.
    // Original port and all peer keys remain unchanged; never resolve via DNS.
    private static String applyOverride(String canonical,String override,int slot) {
        int code=RootlessNativeBridge.validatePeerProfile(canonical);
        if(code==1) return canonical;
        if(code!=9) throw reject(slot,nativeReason(code));
        String ip=override==null?"":override.trim();
        if(ip.isEmpty()) throw reject(slot,"HOSTNAME_REQUIRES_NUMERIC_IP");
        if(ip.length()>64 || !ip.matches("[0-9a-fA-F:.]+") || (!ip.contains(".") && !ip.contains(":")))
            throw reject(slot,"NUMERIC_OVERRIDE_REJECTED");
        String[] lines=canonical.split("\\n",-1);
        int found=0;
        for(int i=0;i<lines.length;i++) if(lines[i].startsWith("Endpoint = ")) {
            String original=lines[i].substring("Endpoint = ".length());
            int colon=original.lastIndexOf(':');
            if(colon<1) throw reject(slot,"ENDPOINT_ADDRESS_OR_PORT_REJECTED");
            lines[i]="Endpoint = "+(ip.contains(":")?"["+ip+"]":ip)+original.substring(colon);
            found++;
        }
        String result=String.join("\n",lines);
        if(found!=1 || RootlessNativeBridge.validatePeerProfile(result)!=1)
            throw reject(slot,"NUMERIC_OVERRIDE_REJECTED");
        return result;
    }
    static String[] prepare(Context context,boolean home,String[] overrides) throws Exception {
        return prepare(context,home,overrides,null);
    }
    static String[] prepare(Context context,boolean home,String[] overrides,String[] localAddresses) throws Exception {
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
            if(localAddresses!=null) {
                String address=null;
                for(String line:c.toWgQuickString().split("\\n")) if(line.startsWith("Address = ")) {
                    for(String part:line.substring("Address = ".length()).split(",")) {
                        String ip=part.trim().split("/",-1)[0];
                        if(ip.contains(":")) continue;
                        if(address!=null) throw reject(i,"MULTIPLE_IPV4_ADDRESSES");
                        try {MultiTunnelIpv4Rewriter.parseIpv4(ip);} catch(IllegalArgumentException invalid){throw reject(i,"IPV4_ADDRESS_REJECTED");}
                        address=ip;
                    }
                }
                if(address==null) throw reject(i,"IPV4_ADDRESS_MISSING");
                localAddresses[i]=address;
            }
            configs[i]=applyOverride(checkedCanonical(c,i,true),overrides!=null&&i<overrides.length?overrides[i]:null,i);
            String pair=c.getInterface().getKeyPair().getPublicKey().toBase64()+":"
                    +c.getPeers().get(0).getPublicKey().toBase64();
            Integer prior=pairs.putIfAbsent(pair,i);
            if(prior!=null) throw reject(i,"DUPLICATE_PEER_IDENTITY_WITH_"+IDS[prior]);
        }
        return configs;
    }
}
