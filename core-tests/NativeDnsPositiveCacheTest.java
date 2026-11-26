package com.yooshastan.wonheeproxy;
import java.util.*;
public class NativeDnsPositiveCacheTest {
 static byte[] q(int id,int type){return new byte[]{(byte)(id>>>8),(byte)id,1,0,0,1,0,0,0,0,0,0,1,'a',3,'c','o','m',0,0,(byte)type,0,1};}
 static byte[] answer(byte[] q,int ttl,int type){
  int len=type==1?4:16;byte[] a=Arrays.copyOf(q,q.length+12+len);a[2]=(byte)0x81;a[3]=(byte)0x80;a[7]=1;
  int p=q.length;a[p]=(byte)0xc0;a[p+1]=12;a[p+3]=(byte)type;a[p+5]=1;a[p+6]=(byte)(ttl>>>24);a[p+7]=(byte)(ttl>>>16);a[p+8]=(byte)(ttl>>>8);a[p+9]=(byte)ttl;a[p+11]=(byte)len;Arrays.fill(a,p+12,a.length,(byte)1);return a;
 }
 static void yes(boolean x){if(!x)throw new AssertionError();}
 public static void main(String[] args){
  NativeDnsPositiveCache c=new NativeDnsPositiveCache();byte[] q=q(1,1),a=answer(q,300,1);
  yes(c.put(q,a,1000));byte[] hit=c.get(q(7,1),2001);yes(hit!=null&&hit[1]==7&&hit[q.length+9]==118);
  yes(c.get(q(7,28),2001)==null);yes(c.get(q(7,1),121000)==null);
  yes(!c.put(q,answer(q,0,1),0));byte[] nx=a.clone();nx[3]=(byte)0x83;yes(!c.put(q,nx,0));
  byte[] extra=a.clone();extra[11]=1;yes(!c.put(q,extra,0));
  byte[] bad=a.clone();bad[q.length+1]=13;yes(!c.put(q,bad,0));
  byte[] q6=q(1,28);yes(c.put(q6,answer(q6,2,28),0));yes(c.get(q(2,28),500)!=null);yes(c.get(q(2,28),1001)==null);
  for(int i=0;i<600;i++){byte[] x=q(1,1);x[13]=(byte)(48+i%70);x[15]=(byte)(48+i/70);yes(c.put(x,answer(x,120,1),0));}
  yes(c.size()==512);c.clear();yes(c.size()==0);
  System.out.println("Bounded positive DNS cache checks PASS");
 }
}
