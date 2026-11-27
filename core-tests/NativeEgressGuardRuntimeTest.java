package com.yooshastan.wonheeproxy;
import java.util.*;
public final class NativeEgressGuardRuntimeTest {
 static void check(boolean b){if(!b)throw new AssertionError();}
 static final class Fake implements NativeEgressGuardRuntime.Runner {
  final Map<Integer,Map<String,List<String>>> tables=new HashMap<>();
  final List<String> mutations=new ArrayList<>();
  Fake(){for(int f:new int[]{4,6}){Map<String,List<String>> m=new LinkedHashMap<>();m.put("OUTPUT",new ArrayList<>(Arrays.asList("-j AFWALL")));m.put("AFWALL",new ArrayList<>(Arrays.asList("-j RETURN")));tables.put(f,m);}}
  public int run(List<String> out,String command){
   for(String cmd:command.split(" && ")){
    String[] a=cmd.split(" ",8);int f=a[0].equals("iptables")?4:6;Map<String,List<String>> m=tables.get(f);String op=a[5];String chain=a.length>6?a[6]:"";String rule=a.length>7?a[7]:"";
    if(op.equals("-S")){
     out.add("-P OUTPUT ACCEPT");for(String c:m.keySet())if(!c.equals("OUTPUT"))out.add("-N "+c);
     for(String c:m.keySet())for(String r:m.get(c))out.add("-A "+c+" "+r);
    }else if(op.equals("-L")){
      int idx=0;for(String r:m.get(chain)){
        String tag=r.substring(r.indexOf("--comment ")+10).split(" ")[0];
        String target=r.substring(r.lastIndexOf("-j ")+3);
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
  check(fake.mutations.stream().noneMatch(x->x.contains(" -F ")||x.contains(" -P ")||x.contains(" -D OUTPUT -j AFWALL")));
  System.out.println("Native egress guard exact ownership transaction PASS");
 }
}
