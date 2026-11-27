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
  for(int port:new int[]{0,34567}){
   NativeEgressGuardPlan d=new NativeEgressGuardPlan("123456abcdef","tun0",10123,1,false,eps,port,true);
   NativeEgressGuardPlan decoded=NativeEgressGuardPlan.decode(d.encode());
   check(decoded.dnsDiagnostics&&decoded.validationPort==port&&decoded.encode().equals(d.encode()));
   NativeEgressGuardPlan old=new NativeEgressGuardPlan("123456abcdef","tun0",10123,1,false,eps,port);
   check(!NativeEgressGuardPlan.decode(old.encode()).dnsDiagnostics);
   for(int f:new int[]{4,6}){
    List<String> rules=d.rules(f);
    check(decoded.rules(f).equals(rules));
    check(rules.stream().filter(x->x.contains("-o wlan0 ")&&x.contains("--dport 53 ")&&x.endsWith("-j DROP")).count()==10);
    for(int owner:new int[]{1051,1073,0,1000})
     check(rules.stream().filter(x->x.contains("-o wlan0 ")&&x.contains("--uid-owner "+owner+" ")&&x.endsWith("-j DROP")).count()==2);
    // Removing only the new terminal drops leaves the original policy,
    // ignoring renumbered exact-ownership comments.
    List<String> unchanged=new ArrayList<>();
    for(String rule:rules)if(!rule.contains("-o wlan0 "))unchanged.add(rule.replaceAll("(^| )-m comment --comment WNE_[a-f0-9]+_[46]_[0-9]+ ","$1"));
    List<String> baseline=new ArrayList<>();
    for(String rule:old.rules(f))baseline.add(rule.replaceAll("(^| )-m comment --comment WNE_[a-f0-9]+_[46]_[0-9]+ ","$1"));
    if(!unchanged.equals(baseline))throw new AssertionError("Baseline rule mismatch IPv"+f+" port="+port+"\nactual="+unchanged+"\nexpected="+baseline);
   }
  }
  NativeEgressGuardPlan dual=new NativeEgressGuardPlan("123456abcdef","tun0",10123,1,false,eps,34567,true,true);
  NativeEgressGuardPlan decoded=NativeEgressGuardPlan.decode(dual.encode());
  check(decoded.validationDual&&decoded.dnsDiagnostics&&decoded.encode().equals(dual.encode()));
  check(Arrays.equals(dual.validationPlan().families(),new int[]{4,6}));
  for(int f:new int[]{4,6}){
   String address=f==4?"127.0.0.1":"::1";
   List<String> rules=dual.rules(f);
   check(decoded.rules(f).equals(rules));
   check(dual.validationPlan().rules(f).size()==2);
   check(dual.validationPlan().rules(f).stream().allMatch(x->x.contains("-o wlan0 ")&&x.contains("--uid-owner 0 ")&&x.contains("--dport 53 ")&&x.endsWith("-j REDIRECT --to-ports 34567")));
   check(rules.get(0).contains("-o lo -d "+address+" ")&&rules.get(0).contains("--uid-owner 0 ")&&rules.get(0).endsWith("-j RETURN"));
   check(rules.get(1).contains("-o lo -d "+address+" ")&&rules.get(1).endsWith("-j DROP"));
   check(rules.stream().noneMatch(x->x.contains("-j ACCEPT")));
   check(rules.get(rules.size()-1).endsWith(f==6?"-j DROP":"-j RETURN"));
  }
  reject(()->new NativeEgressGuardPlan("123456abcdef","tun0",10123,1,false,eps,0,true,true));
  check(!NativeEgressGuardPlan.decode(p.encode()).validationDual);
  NativeEgressGuardPlan v4root=new NativeEgressGuardPlan("123456abcdef","tun0",10123,1,false,eps,34567,true,false,true);
  NativeEgressGuardPlan roundTrip=NativeEgressGuardPlan.decode(v4root.encode());
  check(roundTrip.validationRoot&&!roundTrip.validationDual&&roundTrip.encode().equals(v4root.encode()));
  check(Arrays.equals(v4root.validationPlan().families(),new int[]{4}));
  check(v4root.validationPlan().rules(4).stream().allMatch(x->x.contains("--uid-owner 0 ")));
  check(v4root.rules(4).get(0).contains("--uid-owner 0 "));
  check(v4root.rules(6).equals(new NativeEgressGuardPlan("123456abcdef","tun0",10123,1,false,eps,0,true).rules(6)));
  check(!NativeEgressGuardPlan.decode(p.encode()).validationRoot);
  check(NativeEgressGuardPlan.decode(dual.encode()).validationRoot);
  reject(()->new NativeEgressGuardPlan("123456abcdef","tun0",10123,1,false,eps,0,true,false,true));
  System.out.println("Native egress guard plan and versioned IPv4/dual-stack journal PASS");
 }
}
