package com.yooshastan.wonheeproxy;
public final class NativeDnsFreshBackoffTest {
 private static void check(boolean ok){if(!ok)throw new AssertionError();}
 public static void main(String[] args){
  NativeDnsFreshBackoff b=new NativeDnsFreshBackoff();
  long first=b.begin(100),second=b.begin(100),late=b.begin(100);
  check(first>0&&second==first&&late==first);
  b.finish(first,false,100);check(!b.waiting(100));
  b.finish(second,false,101);check(b.waiting(101)&&b.begin(600)<0);
  b.finish(late,true,102);check(b.waiting(102)); // obsolete generation
  long probe=b.begin(601);check(probe>first&&b.begin(601)<0);
  b.finish(probe,false,602);check(b.waiting(1601)&&b.begin(1601)<0);
  long retry=b.begin(1602);check(retry>probe&&b.begin(1602)<0);
  b.finish(retry,true,1603);check(!b.waiting(1603)&&b.begin(1603)>0);
  long fresh=b.begin(1604);b.finish(fresh,false,1604);check(!b.waiting(1604));
  System.out.println("Fresh QUIC backoff and half-open trial PASS");
 }
}
