package com.yooshastan.wonheeproxy;
import java.io.*;
import java.nio.charset.StandardCharsets;
public class NativeTransferBodyTest {
 static void read(String body,String headers,int n)throws Exception{
  int[] count={0};NativeTransferBody.read(new ByteArrayInputStream(body.getBytes(StandardCharsets.US_ASCII)),headers,n,v->count[0]=v);
  if(count[0]!=n)throw new AssertionError();
 }
 static void bad(String body,String headers,int n)throws Exception{
  try{read(body,headers,n);throw new AssertionError("invalid framing accepted");}catch(IOException expected){}
 }
 public static void main(String[] args)throws Exception{
  read("abcd","Content-Length: 4\r\n",4);
  read("2\r\nab\r\n2\r\ncd\r\n0\r\n\r\n","Transfer-Encoding: chunked\r\n",4);
  bad("abc","Content-Length: 4\r\n",4);
  bad("abcd","Content-Length: 5\r\n",4);
  bad("abcd","Content-Length: 4\r\nTransfer-Encoding: chunked\r\n",4);
  bad("5\r\nabcde\r\n0\r\n\r\n","Transfer-Encoding: chunked\r\n",4);
  bad("abcd","Content-Length: 4\r\nContent-Encoding: gzip\r\n",4);
  System.out.println("Native bounded transfer framing PASS");
 }
}
