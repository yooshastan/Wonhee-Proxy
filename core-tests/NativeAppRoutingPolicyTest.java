package com.yooshastan.wonheeproxy;
import java.util.*;
public class NativeAppRoutingPolicyTest {
 static int ip(String s){return MultiTunnelIpv4Rewriter.parseIpv4(s);}
 static NativeAppRoutingPolicy.Key key(String addr,int proto,int port){return new NativeAppRoutingPolicy.Key(ip(addr),40000,port,proto);}
 static void eq(int a,int b){if(a!=b)throw new AssertionError(a+" != "+b);}
 public static void main(String[] args){
  int[] cat=new int[AppUseCategories.LABELS.length],pro=new int[NativeAppRoutingPolicy.SELECTORS.length];
  Arrays.fill(cat,3);Arrays.fill(pro,3);
  cat[AppUseCategories.REGIONAL]=1;pro[1]=0;pro[4]=-1;
  NativeAppRoutingPolicy p=new NativeAppRoutingPolicy(new NativeAppRoutingPolicy.Prefix("10.0.0.0/24"),0,cat,pro);
  NativeAppRoutingPolicy.App regional=new NativeAppRoutingPolicy.App(AppUseCategories.REGIONAL,3),direct=new NativeAppRoutingPolicy.App(AppUseCategories.REGIONAL,0),blocked=new NativeAppRoutingPolicy.App(AppUseCategories.PRIVATE,-1);
  eq(p.choose(key("1.1.1.1",6,443),regional,false),0);
  eq(p.choose(key("8.8.8.8",6,80),regional,false),1);
  eq(p.choose(key("8.8.8.8",6,80),direct,false),0);
  eq(p.choose(key("8.8.8.8",6,80),blocked,false),-1);
  eq(p.choose(key("10.0.0.169",6,443),regional,false),2);
  eq(p.choose(key("10.0.1.1",6,443),regional,false),-1);
  eq(p.choose(key("100.64.0.1",6,443),regional,false),-1);
  eq(p.choose(key("1.1.1.1",17,53),null,true),-1);
  eq(p.choose(key("8.8.8.8",6,443),null,false),-1);
  eq(p.choose(key("8.8.8.8",6,443),null,true),-1);
  eq(p.choose(key("8.8.8.8",6,443),blocked,false),-1);
  eq(p.choose(key("10.0.0.169",6,443),blocked,false),-1);
   cat[AppUseCategories.REGIONAL]=-1;
   NativeAppRoutingPolicy p2=new NativeAppRoutingPolicy(new NativeAppRoutingPolicy.Prefix("10.0.0.0/24"),0,cat,pro);
   eq(p2.choose(key("8.8.8.8",6,443),direct,false),-1);
   eq(p2.choose(key("10.0.0.169",6,443),direct,false),-1);
   eq(NativeAppRoutingPolicy.selector(key("8.8.8.8",17,123)),15);
   eq(NativeAppRoutingPolicy.selector(key("8.8.8.8",6,25)),14);
   NativeAppRoutingPolicy.Ledger l=new NativeAppRoutingPolicy.Ledger();
  NativeAppRoutingPolicy.Key tcp=key("8.8.8.8",6,443),udp=key("1.1.1.1",17,53);
  if(l.admit(tcp,false,10001,0,1)!=null||l.reply(tcp,0,1))throw new AssertionError("unowned flow");
  if(l.admit(tcp,true,10001,0,1)==null||!l.reply(tcp,0,2)||l.reply(tcp,1,2))throw new AssertionError("ownership");
  if(l.admit(tcp,true,10002,1,2)!=null||l.admit(tcp,true,10001,1,2)!=null)throw new AssertionError("flow migration");
  if(l.admit(udp,false,10001,1,1)==null||!l.reply(udp,1,2)||l.reply(udp,0,2)||l.reply(udp,1,60001))throw new AssertionError("UDP expiry");
  if(l.reply(tcp,0,300001)||l.admit(tcp,false,10001,0,300001)!=null)throw new AssertionError("TCP expiry");
  try{new NativeAppRoutingPolicy.Prefix("0.0.0.0/0");throw new AssertionError();}catch(IllegalArgumentException expected){}
  try{new NativeAppRoutingPolicy.Prefix("192.168.0.0/8");throw new AssertionError();}catch(IllegalArgumentException expected){}
  System.out.println("Native app routing policy/ownership PASS");
 }
}
