package com.yooshastan.wonheeproxy;
import java.util.*;
import java.io.IOException;
public class NativeProtectedDnsMessageTest {
 static byte[] query(){return new byte[]{1,2,1,0,0,1,0,0,0,0,0,0,3,'a','d','s',7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};}
 public static void main(String[] args)throws Exception{
  byte[] q=NativeProtectedDnsMessage.normalize(query());
  if(!NativeProtectedDnsMessage.question(q).name.equals("ads.example.com"))throw new AssertionError();
  if(!NativeProtectedDnsMessage.blocked("ads.example.com",Collections.singleton("example.com"))||NativeProtectedDnsMessage.blocked("notexample.com",Collections.singleton("example.com")))throw new AssertionError("suffix boundary");
  byte[] nx=NativeProtectedDnsMessage.error(q,3,false);if((nx[3]&15)!=3||NativeProtectedDnsMessage.validate(q,nx)!=nx)throw new AssertionError();
  byte[] wrong=nx.clone();wrong[0]++;
  try{NativeProtectedDnsMessage.validate(q,wrong);throw new AssertionError();}catch(IOException expected){}
  byte[] packet=new byte[28+q.length];packet[0]=0x45;packet[9]=17;packet[12]=10;packet[13]=(byte)253;packet[15]=1;Arrays.fill(packet,16,20,(byte)1);NativeProtectedDnsMessage.put(packet,20,40000);NativeProtectedDnsMessage.put(packet,22,53);
  byte[] reply=NativeProtectedDnsMessage.reply(packet,nx);if(NativeProtectedDnsMessage.u16(reply,20)!=53||NativeProtectedDnsMessage.u16(reply,22)!=40000||NativeProtectedDnsMessage.u16(reply,24)!=nx.length+8)throw new AssertionError("UDP response");
  int sum=0;for(int i=0;i<20;i+=2)sum+=NativeProtectedDnsMessage.u16(reply,i);while((sum>>>16)!=0)sum=(sum&65535)+(sum>>>16);if(sum!=65535)throw new AssertionError("checksum");
  byte[] invalid=q.clone();invalid[12]=(byte)192;try{NativeProtectedDnsMessage.normalize(invalid);throw new AssertionError();}catch(IOException expected){}
  System.out.println("Protected DNS message checks PASS");
 }
}
