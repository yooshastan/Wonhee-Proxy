package com.yooshastan.wonheeproxy;
import java.util.*;
public final class NativeEgressGuardRuntimeTest {
 static void check(boolean b){if(!b)throw new AssertionError();}
 static final class Fake implements NativeEgressGuardRuntime.Runner {
  final Map<Integer,Map<String,List<String>>> tables=new HashMap<>();
  final List<String> mutations=new ArrayList<>();
  Fake(){for(int f:new int[]{4,6,14,16}){Map<String,List<String>> m=new LinkedHashMap<>();m.put("OUTPUT",new ArrayList<>(Arrays.asList("-j AFWALL")));m.put("AFWALL",new ArrayList<>(Arrays.asList("-j RETURN")));tables.put(f,m);}}
  public int run(List<String> out,String command){
   for(String cmd:command.split(" && ")){
    String[] a=cmd.split(" ",8);int f=(a[0].equals("iptables")?4:6)+(a[4].equals("nat")?10:0);Map<String,List<String>> m=tables.get(f);String op=a[5];String chain=a.length>6?a[6]:"";String rule=a.length>7?a[7]:"";
    if(op.equals("-S")){
     out.add("-P OUTPUT ACCEPT");for(String c:m.keySet())if(!c.equals("OUTPUT"))out.add("-N "+c);
     for(String c:m.keySet())for(String r:m.get(c))out.add("-A "+c+" "+r);
    }else if(op.equals("-L")){
      int idx=0;for(String r:m.get(chain)){
        String tag=r.substring(r.indexOf("--comment ")+10).split(" ")[0];
        String target=r.substring(r.lastIndexOf("-j ")+3).split(" ")[0];
        out.add((++idx)+" 100 "+target+" all -- * * 0.0.0.0/0 0.0.0.0/0 /* "+tag+" */");
      }
    }else if(op.equals("-C")){if(!m.containsKey(chain)||!m.get(chain).contains(rule))return 1;}
    else{
     mutations.add(cmd);
     if(op.equals("-N")){if(m.containsKey(chain))return 1;m.put(chain,new ArrayList<>());}
     else if(op.equals("-X")){if(!m.containsKey(chain)||!m.get(chain).isEmpty())return 1;m.remove(chain);}
     else if(op.equals("-A")){if(!m.containsKey(chain))return 1;m.get(chain).add(rule);}
     else if(op.equals("-I")){if(!m.containsKey(chain)||!rule.startsWith("1 "))return 1;m.get(chain).add(0,rule.substring(2));}
     else if(op.equals("-D")){if(!m.containsKey(chain)||!m.get(chain).remove(rule))return 1;}
     else throw new AssertionError("unexpected command "+cmd);
    }
   }return 0;
  }
 }
 interface Trial{void run()throws Exception;}
 static void reject(Trial r)throws Exception{try{r.run();throw new AssertionError("accepted");}catch(IllegalStateException expected){}}
 public static void main(String[] args)throws Exception{
  List<String> endpoints=Arrays.asList("192.0.2.1:51820","198.51.100.1:443");
  NativeEgressGuardPlan p=new NativeEgressGuardPlan("123456abcdef","tun0",10123,1,false,endpoints);
  Fake fake=new Fake();NativeEgressGuardRuntime runtime=new NativeEgressGuardRuntime(fake);
  runtime.install(p);runtime.verify(p);
  String counters=runtime.counters(p);check(counters.contains("DNS53=")&&counters.contains("DNS853=")&&counters.contains("mDNS=")&&counters.contains("SSDP=")&&counters.contains("other="));
  check(fake.tables.get(4).get("OUTPUT").get(1).equals("-j AFWALL"));
  List<String> rules=fake.tables.get(6).get(p.chain(6));
  Collections.swap(rules,0,1);reject(()->runtime.verify(p));Collections.swap(rules,0,1);
  fake.tables.get(4).get("OUTPUT").add(0,"-j RETURN");reject(()->runtime.verify(p));fake.tables.get(4).get("OUTPUT").remove(0);
  rules.add("-j ACCEPT");int before=fake.mutations.size();reject(()->runtime.remove(p));check(fake.mutations.size()==before);rules.remove(rules.size()-1);
  runtime.remove(p);
  for(int f:new int[]{4,6}){check(fake.tables.get(f).get("OUTPUT").equals(Arrays.asList("-j AFWALL")));check(!fake.tables.get(f).containsKey(p.chain(f)));check(fake.tables.get(f).get("AFWALL").equals(Arrays.asList("-j RETURN")));}
  // Simulated crash during installation, before anchors.
  fake.tables.get(4).put(p.chain(4),new ArrayList<>(p.rules(4).subList(0,3)));
  runtime.remove(p);check(!fake.tables.get(4).containsKey(p.chain(4)));
  NativeEgressGuardPlan strict=new NativeEgressGuardPlan("123456abcdef","tun0",10123,2,false,endpoints);
  before=fake.mutations.size();reject(()->runtime.install(strict));check(fake.mutations.size()==before);
  // Narrow activation must still reject strict mode; explicit opt-in is separate.
  reject(()->runtime.installStrict(p));check(fake.mutations.size()==before);
  NativeEgressGuardPlan strictDiscovery=new NativeEgressGuardPlan("123456abcdef","tun0",10123,2,true,endpoints);
  reject(()->runtime.installStrict(strictDiscovery));check(fake.mutations.size()==before);
  check(runtime.offlineState(strict).equals("Absent"));
  runtime.installStrict(strict);runtime.verify(strict);
  for(int f:new int[]{4,6}){
   List<String> sr=strict.rules(f);check(sr.get(sr.size()-1).endsWith("-j DROP"));
   check(sr.stream().noneMatch(x->x.endsWith("-j ACCEPT")));
   check(fake.tables.get(f).get("OUTPUT").get(1).equals("-j AFWALL"));
  }
  // New runtime instance: simulated process death with persistent journal and rules.
  NativeEgressGuardRuntime restarted=new NativeEgressGuardRuntime(fake);
  NativeEgressGuardPlan restored=NativeEgressGuardPlan.decode(strict.encode());
  before=fake.mutations.size();
  check(restarted.offlineState(restored).equals("Exact rules and first anchors present"));
  check(fake.mutations.size()==before);
  fake.tables.get(4).get("OUTPUT").add(0,"-j RETURN");
  check(restarted.offlineState(restored).equals("Partial or moved"));check(fake.mutations.size()==before);
  fake.tables.get(4).get("OUTPUT").remove(0);
  fake.tables.get(6).get(strict.chain(6)).add("-j ACCEPT");
  reject(()->restarted.offlineState(restored));check(fake.mutations.size()==before);
  fake.tables.get(6).get(strict.chain(6)).remove(strict.rules(6).size());
  restarted.remove(restored);check(restarted.offlineState(restored).equals("Absent"));
  for(int f:new int[]{4,6})check(fake.tables.get(f).size()==2&&fake.tables.get(f).get("OUTPUT").equals(Arrays.asList("-j AFWALL")));
  // Journal persisted but kernel state absent (e.g. reboot): never report protected.
  check(restarted.offlineState(restored).equals("Absent"));
  check(fake.mutations.stream().noneMatch(x->x.contains(" -F ")||x.contains(" -P ")||x.contains(" -D OUTPUT -j AFWALL")));
  NativeEgressGuardPlan bridge=new NativeEgressGuardPlan("123456abcdef","tun0",10123,1,false,endpoints,34567);
  check(NativeEgressGuardPlan.decode(bridge.encode()).validationPort==34567);
  check(NativeEgressGuardPlan.decode(p.encode()).validationPort==0);
  check(bridge.rules(6).equals(p.rules(6)));
  check(bridge.rules(4).get(0).contains("--uid-owner 1073")&&bridge.rules(4).get(1).endsWith("-j DROP"));
  NativeValidationDnsPlan nat=bridge.validationPlan();
  check(nat.rules(4).size()==2&&nat.rules(4).stream().allMatch(x->x.contains("-o wlan0")&&x.contains("--uid-owner 1073")&&x.contains("--dport 53")&&x.endsWith("-j REDIRECT --to-ports 34567")));
  runtime.install(bridge);runtime.installValidation(nat);runtime.verify(nat);runtime.verify(bridge);
  List<String> nr=fake.tables.get(14).get(nat.chain(4));nr.add("-j RETURN");
  before=fake.mutations.size();reject(()->runtime.remove(nat));check(fake.mutations.size()==before);nr.remove(nr.size()-1);
  runtime.remove(nat);runtime.remove(bridge);
  check(fake.tables.get(14).get("OUTPUT").equals(Arrays.asList("-j AFWALL")));
  check(fake.tables.get(14).get("AFWALL").equals(Arrays.asList("-j RETURN")));
  NativeEgressGuardPlan diagnostic=new NativeEgressGuardPlan("123456abcdef","tun0",10123,1,false,endpoints,34567,true);
  runtime.install(diagnostic);runtime.installValidation(diagnostic.validationPlan());
  check(runtime.validationCounters(diagnostic.validationPlan()).equals("NAT IPv4 redirect UDP=1 TCP=2 · IPv6 redirect not installed"));
  String detail=runtime.counters(diagnostic);
  // Fake assigns row number as count. Assert each owner appears, and test
  // exact sum by independently reading expected row positions.
  for(int f:new int[]{4,6}){
   List<String> dr=diagnostic.rules(f);long[] sums=new long[6];int[] owners={1051,1073,0,1000};
   for(int i=0;i<dr.size();i++){
    String rule=dr.get(i);if(!rule.contains("--dport 53 ")||!rule.endsWith("-j DROP"))continue;
    int bucket=5;
    if(rule.contains("-o wlan0 ")){bucket=4;for(int j=0;j<4;j++)if(rule.contains("--uid-owner "+owners[j]+" "))bucket=j;}
    sums[bucket]+=i+1;
   }
   String summary=detail.split(" · ")[f==4?0:1];
   check(summary.contains("DNS53="+Arrays.stream(sums).sum()+" "));
   check(summary.contains("1051="+sums[0]+" 1073="+sums[1]+" root="+sums[2]+" system="+sums[3]+" other/unmatched="+sums[4]+" non-Wi-Fi="+sums[5]));
  }
  runtime.remove(diagnostic.validationPlan());runtime.remove(diagnostic);
  check(fake.tables.get(14).get("OUTPUT").equals(Arrays.asList("-j AFWALL")));
  NativeEgressGuardPlan dual=new NativeEgressGuardPlan("123456abcdef","tun0",10123,1,false,endpoints,34567,true,true);
  NativeValidationDnsPlan dn=dual.validationPlan();
  runtime.install(dual);runtime.installValidation(dn);runtime.verify(dual);runtime.verify(dn);
  check(runtime.validationCounters(dn).equals("NAT IPv4 redirect UDP=1 TCP=2 · NAT IPv6 redirect UDP=1 TCP=2"));
  List<String> six=fake.tables.get(16).get(dn.chain(6));six.add("-j RETURN");
  before=fake.mutations.size();reject(()->runtime.remove(dn));check(fake.mutations.size()==before);six.remove(six.size()-1);
  runtime.remove(dn);runtime.remove(dual);
  for(int f:new int[]{4,6,14,16}){
   check(fake.tables.get(f).get("OUTPUT").equals(Arrays.asList("-j AFWALL")));
   check(fake.tables.get(f).get("AFWALL").equals(Arrays.asList("-j RETURN")));
   check(fake.tables.get(f).size()==2);
  }
  // Interrupted NAT install: only IPv4 redirect exists, IPv6 never created.
  fake.tables.get(14).put(dn.chain(4),new ArrayList<>(dn.rules(4)));
  runtime.remove(dn);check(fake.tables.get(14).size()==2&&fake.tables.get(16).size()==2);
  NativeEgressGuardPlan v4root=new NativeEgressGuardPlan("123456abcdef","tun0",10123,1,false,endpoints,34567,true,false,true);
  NativeValidationDnsPlan v4nat=v4root.validationPlan();
  // Model a kernel with no IPv6 NAT table at all.
  fake.tables.remove(16);
  runtime.install(v4root);runtime.installValidation(v4nat);runtime.verify(v4root);runtime.verify(v4nat);
  check(runtime.validationCounters(v4nat).equals("NAT IPv4 redirect UDP=1 TCP=2 · IPv6 redirect not installed"));
  runtime.remove(v4nat);runtime.remove(v4root);
  for(int f:new int[]{4,6,14})check(fake.tables.get(f).size()==2&&fake.tables.get(f).get("OUTPUT").equals(Arrays.asList("-j AFWALL")));
  System.out.println("Native egress guard, dual-stack and IPv4-only validation NAT rollback PASS");
 }
}
