package com.yooshastan.wonheeproxy;
import java.util.*;
public class NativeRoutingUiModelsTest {
 public static void main(String[] args){
  List<String> r=NativeHomeRoutes.fromConfig("[Interface]\nAddress = 10.0.0.1/24\n[Peer]\nAllowedIPs = 0.0.0.0/0, 10.0.0.169/32, 192.168.1.0/24, ::/0, 10.0.0.169/32, 10.0.0.1/24\n");
  if(!r.equals(Arrays.asList("10.0.0.169/32","192.168.1.0/24")))throw new AssertionError(r);
  if(NativeRoutingMetrics.perSecond(1000,3048,2000)!=1024||NativeRoutingMetrics.perSecond(200,100,1000)!=0||NativeRoutingMetrics.perSecond(0,1,0)!=0)throw new AssertionError();
  if(!NativeRoutingMetrics.rate(1024).equals("1.0 KiB/s"))throw new AssertionError();
  System.out.println("Home route suggestions and live rate metrics PASS");
 }
}
