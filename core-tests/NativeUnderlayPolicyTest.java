package com.yooshastan.wonheeproxy;
import java.util.*;
public final class NativeUnderlayPolicyTest {
 static void eq(long a,long b){if(a!=b)throw new AssertionError(a+" != "+b);}
 static void yes(boolean v){if(!v)throw new AssertionError();}
 public static void main(String[] args){
  Map<Long,Integer> m=new HashMap<>();m.put(421L,2);m.put(447L,1);m.put(448L,1);
  eq(NativeUnderlayPolicy.pick(0,421,421,m),447);
  eq(NativeUnderlayPolicy.pick(0,448,447,m),448);
  eq(NativeUnderlayPolicy.pick(1,421,447,m),447);
  eq(NativeUnderlayPolicy.pick(1,421,0,m),421);
  eq(NativeUnderlayPolicy.pick(2,447,447,m),421);
  eq(NativeUnderlayPolicy.pick(3,421,447,m),421);
  m.remove(421L);eq(NativeUnderlayPolicy.pick(3,421,447,m),447);
  eq(NativeUnderlayPolicy.pick(2,0,0,m),447);
  m.clear();eq(NativeUnderlayPolicy.pick(0,421,447,m),0);
  NativeUnderlayPolicy.Debounce d=new NativeUnderlayPolicy.Debounce();
  yes(!d.due(421,447,100));yes(!d.due(421,447,2099));yes(d.due(421,447,2100));
  yes(!d.due(421,448,2101));yes(!d.due(421,421,4101));yes(!d.due(421,448,4102));yes(d.due(421,448,6102));
  d.reset();yes(!d.due(421,447,9000));yes(!d.due(421,447,8000));
  System.out.println("Underlay preference and debounce PASS");
 }
}
