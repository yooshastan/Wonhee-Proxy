package com.yooshastan.wonheeproxy;
import java.util.Locale;
final class NativeRoutingMetrics {
    static long perSecond(long before,long after,long millis){
        if(before<0||after<before||millis<=0)return 0;
        double rate=(after-before)*1000.0/millis;
        return rate>=Long.MAX_VALUE?Long.MAX_VALUE:(long)rate;
    }
    static String rate(long value){
        if(value<1024)return Math.max(0,value)+" B/s";
        if(value<1024*1024)return String.format(Locale.US,"%.1f KiB/s",value/1024.0);
        return String.format(Locale.US,"%.1f MiB/s",value/1048576.0);
    }
}
