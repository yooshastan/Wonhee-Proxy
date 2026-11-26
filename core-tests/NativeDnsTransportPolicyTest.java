package com.yooshastan.wonheeproxy;
public final class NativeDnsTransportPolicyTest {
 public static void main(String[] args){
  for(int p=-1;p<5;p++)for(int m=-1;m<4;m++){
   boolean want=p>=0&&p<4&&(m==0||m==1&&(p==1||p==2)||m==2&&(p==0||p==1));
   if(NativeDnsTransportPolicy.supports(p,m)!=want)throw new AssertionError();
  }
  if(NativeDnsTransportPolicy.port(2)!=443||NativeDnsTransportPolicy.port(1)!=853||NativeDnsTransportPolicy.protocol(1)!=17||NativeDnsTransportPolicy.protocol(0)!=6)throw new AssertionError();
  System.out.println("Encrypted DNS provider/transport matrix PASS");
 }
}
