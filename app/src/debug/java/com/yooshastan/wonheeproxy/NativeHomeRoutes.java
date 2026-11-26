package com.yooshastan.wonheeproxy;
import java.util.*;
/** Suggest only explicit, canonical private IPv4 AllowedIPs. Never broaden routes. */
final class NativeHomeRoutes {
    static List<String> fromConfig(String config){
        Set<String> found=new LinkedHashSet<>();
        if(config==null||config.length()>65536)return Collections.emptyList();
        boolean peer=false;
        for(String raw:config.split("\\r?\\n")){
            String line=raw.split("#",2)[0].trim();
            if(line.startsWith("[")){peer=line.equalsIgnoreCase("[Peer]");continue;}
            int eq=line.indexOf('=');if(!peer||eq<0||!line.substring(0,eq).trim().equalsIgnoreCase("AllowedIPs"))continue;
            for(String item:line.substring(eq+1).split(",")){
                String value=item.trim();
                try{new NativeAppRoutingPolicy.Prefix(value);found.add(value);}catch(IllegalArgumentException ignored){}
            }
        }
        return new ArrayList<>(found);
    }
}
