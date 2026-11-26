package com.yooshastan.wonheeproxy;
public final class NativeRecoveryPlanTest {
 public static void main(String[] args){
  long total=0;
  for(int i=0;i<5;i++){long actual=NativeRecoveryPlan.delay(i);if(actual!=(1000L<<i))throw new AssertionError();total+=actual;}
  if(total!=31000)throw new AssertionError();
  for(int n:new int[]{-1,5}){try{NativeRecoveryPlan.delay(n);throw new AssertionError();}catch(IllegalArgumentException expected){}}
  System.out.println("Bounded recovery backoff PASS");
 }
}
