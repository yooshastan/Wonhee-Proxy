package com.yooshastan.wonheeproxy;
import java.util.*;
public final class NativeEgressGuardPlanTest {
 static void check(boolean b){if(!b)throw new AssertionError();}
 static void reject(Runnable r){try{r.run();throw new AssertionError("accepted");}catch(IllegalArgumentException expected){}}
 public static void main(String[] args){
  List<String> eps=Arrays.asList("198.51.100.1:443","[2001:db8::1]:51820","192.0.2.1:53");
  NativeEgressGuardPlan p=new NativeEgressGuardPlan("123456abcdef","tun0",10123,1,false,eps);
  check(p.encode().equals(NativeEgressGuardPlan.decode(p.encode()).encode()));
  for(int f:new int[]{4,6}){
   List<String> r=p.rules(f);
   check(r.get(0).contains("-o lo ")&&r.get(1).contains("-o tun0 "));
   check(r.stream().noneMatch(x->x.contains("-j ACCEPT")));
   check(r.stream().anyMatch(x->x.contains("--dport 53 ")&&x.endsWith("-j DROP")));
   check(r.stream().anyMatch(x->x.contains("--dport 853 ")&&x.endsWith("-j DROP")));
   check(r.stream().anyMatch(x->x.contains("--dport 5353 ")&&x.endsWith("-j DROP")));
   check(r.get(r.size()-1).endsWith(f==6?"-j DROP":"-j RETURN"));
   check(r.stream().anyMatch(x->x.contains("--uid-owner 10123")&&x.contains("-d ")));
  }
  check(p.rules(4).stream().anyMatch(x->x.contains("-d 192.0.2.1 --dport 53 -m owner")));
  NativeEgressGuardPlan strict=new NativeEgressGuardPlan("123456abcdef","tun17",10123,2,true,eps);
  check(strict.rules(4).get(strict.rules(4).size()-1).endsWith("-j DROP"));
  check(strict.rules(6).stream().anyMatch(x->x.contains("-d ff02::fb --dport 5353")&&x.endsWith("-j RETURN")));
  check(strict.rules(4).stream().noneMatch(x->x.contains("--dport 4500")));
  reject(()->new NativeEgressGuardPlan("123456abcdef","wlan0;id",10123,1,false,eps));
  reject(()->new NativeEgressGuardPlan("123456abcdef","tun0",0,1,false,eps));
  reject(()->new NativeEgressGuardPlan("123456abcdef","tun0",10123,3,false,eps));
  reject(()->new NativeEgressGuardPlan("123456abcdef","tun0",10123,1,false,Arrays.asList("host.invalid:443","192.0.2.1:53")));
  reject(()->NativeEgressGuardPlan.endpoints(new String[]{"Endpoint = 192.0.2.1:53\nEndpoint = 192.0.2.2:53"}));
  System.out.println("Native egress guard plan PASS");
 }
}
