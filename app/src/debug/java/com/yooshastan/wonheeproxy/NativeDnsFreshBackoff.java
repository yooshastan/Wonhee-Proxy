package com.yooshastan.wonheeproxy;
/** Per-relay bounded fresh-connection circuit; stale pooled failures never enter it. */
final class NativeDnsFreshBackoff {
    private int failures;
    private long retryAfter,epoch=1;
    private boolean trial;
    synchronized long begin(long now){
        if(retryAfter!=0){
            if(now<retryAfter||trial)return -1;
            trial=true;
        }
        return epoch;
    }
    synchronized void finish(long ticket,boolean ok,long now){
        if(ticket!=epoch)return; // Ignore late results from a prior circuit generation.
        if(ok){failures=0;retryAfter=0;trial=false;return;}
        failures=Math.min(6,failures+1);
        if(failures>=2){
            retryAfter=now+Math.min(8000L,500L<<(failures-2));
            trial=false;epoch++;
        }
    }
    // At most two total attempts; never retry a reused failure twice or a TLS/validation failure.
    static boolean canRetryHandshake(int freshAttempt,boolean reusedFailed,boolean closed,boolean handshakeTimeout){
        return freshAttempt==0&&!reusedFailed&&!closed&&handshakeTimeout;
    }
    synchronized boolean waiting(long now){return retryAfter!=0&&(now<retryAfter||trial);}
}
