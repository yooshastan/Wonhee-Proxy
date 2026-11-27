package com.yooshastan.wonheeproxy;

import java.util.Map;

/** Pure candidate policy; Android validation and authenticated peer evidence are distinct. */
final class NativeUnderlayPolicy {
    static final int WIFI_FIRST=0,SYSTEM=1,CELL_FIRST=2,STICKY=3;
    static final int WIFI=1,CELL=2;
    static final long SETTLE_MS=2000, FAILED_TRIAL_COOLDOWN_MS=120000;
    static final String[] LABELS={"Prefer Wi-Fi","Android best available","Prefer cellular","Maintain current connection"};
    static boolean valid(int mode){return mode>=0&&mode<LABELS.length;}
    // Initial startup never relaxes Android validation. During a verified
    // root guard, physical eligibility permits a handshake trial, not forwarding.
    static boolean sessionCandidate(boolean physicalEligible,boolean validated,boolean guarded){
        return physicalEligible&&(validated||guarded);
    }
    static boolean retainUnvalidated(int mode,boolean guarded,boolean physicalEligible,boolean validated,boolean peerReady){
        return guarded&&physicalEligible&&!validated&&peerReady&&(mode==SYSTEM||mode==STICKY);
    }
    static boolean trialAllowed(long now,long cooldownUntil){return now>=cooldownUntil;}
    static long pick(int mode,long current,long best,Map<Long,Integer> usable){
        if(!valid(mode))throw new IllegalArgumentException();
        if(mode==STICKY&&usable.containsKey(current))return current;
        if(mode==SYSTEM&&usable.containsKey(best))return best;
        if(mode==SYSTEM&&usable.containsKey(current))return current;
        int preferred=mode==CELL_FIRST?CELL:WIFI;
        if(usable.getOrDefault(current,0)==preferred)return current;
        if(usable.getOrDefault(best,0)==preferred)return best;
        long found=0;
        for(Map.Entry<Long,Integer> e:usable.entrySet())if(e.getValue()==preferred&&(found==0||Long.compareUnsigned(e.getKey(),found)<0))found=e.getKey();
        if(found!=0)return found;
        if(usable.containsKey(current))return current;
        if(usable.containsKey(best))return best;
        for(long id:usable.keySet())if(found==0||Long.compareUnsigned(id,found)<0)found=id;
        return found;
    }
    static final class Debounce {
        private long pending,since;
        void reset(){pending=0;since=0;}
        boolean due(long current,long candidate,long now){
            if(candidate==0||candidate==current){reset();return false;}
            if(pending!=candidate||now<since){pending=candidate;since=now;return false;}
            return now-since>=SETTLE_MS;
        }
    }
}
