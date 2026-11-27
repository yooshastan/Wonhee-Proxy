package com.yooshastan.wonheeproxy;
import java.util.*;
import java.io.*;
public final class NativeValidationDnsPolicyTest {
 static void check(boolean b){if(!b)throw new AssertionError();}
 static void reject(byte[] q)throws Exception{try{NativeValidationDnsPolicy.canonical(q,99);throw new AssertionError("accepted");}catch(IOException expected){}}
 public static void main(String[] args)throws Exception{
  for(String name:new String[]{"www.google.com","connectivitycheck.gstatic.com","play.googleapis.com"}){
   for(int type:new int[]{1,28}){
    byte[] raw=NativeProtectedDnsMessage.testQuery(name.toUpperCase(Locale.ROOT),12);
    NativeProtectedDnsMessage.put(raw,raw.length-4,type);
    byte[] q=NativeValidationDnsPolicy.canonical(raw,99);
    check(NativeProtectedDnsMessage.u16(q,0)==99);
    check(NativeProtectedDnsMessage.question(q).type==type);
    check(NativeProtectedDnsMessage.question(q).name.equals(name));
    byte[] response=NativeProtectedDnsMessage.error(q,2,false);
    byte[] restored=NativeValidationDnsPolicy.response(raw,q,response,true);
    check(NativeProtectedDnsMessage.u16(restored,0)==12);
    check((NativeProtectedDnsMessage.u16(restored,2)&15)==2);
    check(Arrays.equals(Arrays.copyOfRange(raw,12,raw.length),Arrays.copyOfRange(restored,12,restored.length)));
    byte[] wrong=response.clone();NativeProtectedDnsMessage.put(wrong,0,100);
    try{NativeValidationDnsPolicy.response(raw,q,wrong,false);throw new AssertionError("accepted mismatched ID");}catch(IOException expected){}
   }
  }
  reject(NativeProtectedDnsMessage.testQuery("example.com",12));
  reject(NativeProtectedDnsMessage.testQuery("www.google.com.evil.test",12));
  reject(NativeProtectedDnsMessage.testQuery("evil.www.google.com",12));
  byte[] txt=NativeProtectedDnsMessage.testQuery("www.google.com",12);
  NativeProtectedDnsMessage.put(txt,txt.length-4,16);reject(txt);
  reject(new byte[12]);
  System.out.println("Validation DNS exact names, canonical questions and response correlation PASS");
 }
}
