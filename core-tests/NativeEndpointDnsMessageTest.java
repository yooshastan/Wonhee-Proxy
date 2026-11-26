package com.yooshastan.wonheeproxy;
import java.io.*;
import java.util.Arrays;
public class NativeEndpointDnsMessageTest {
    static byte[] answer(int type,byte[] ip)throws Exception{
        byte[] q=NativeEndpointDnsMessage.query("example.com",123,type);
        q[2]=(byte)0x81;q[3]=(byte)0x80;q[7]=1;
        ByteArrayOutputStream b=new ByteArrayOutputStream();b.write(q);
        DataOutputStream o=new DataOutputStream(b);o.writeShort(0xc00c);o.writeShort(type);o.writeShort(1);o.writeInt(60);o.writeShort(ip.length);o.write(ip);
        return b.toByteArray();
    }
    static void bad(byte[] b,int id,int type)throws Exception{
        try{NativeEndpointDnsMessage.parse(b,"example.com",id,type);throw new AssertionError("accepted bad message");}
        catch(IOException expected){}
    }
    public static void main(String[] args)throws Exception{
        byte[] a=answer(1,new byte[]{1,2,3,4});
        NativeEndpointDnsMessage.Answer result=NativeEndpointDnsMessage.parse(a,"example.com",123,1);
        if(!result.ip.equals("1.2.3.4")||result.ttl!=60)throw new AssertionError();
        bad(a,124,1);bad(a,123,28);bad(Arrays.copyOf(a,a.length-1),123,1);
        byte[] truncated=a.clone();truncated[2]|=2;bad(truncated,123,1);
        byte[] badptr=a.clone();int at=NativeEndpointDnsMessage.query("example.com",123,1).length;badptr[at+1]=(byte)at;bad(badptr,123,1);
        byte[] v6=new byte[16];v6[0]=0x26;v6[1]=0x06;v6[15]=1;
        if(NativeEndpointDnsMessage.parse(answer(28,v6),"example.com",123,28)==null)throw new AssertionError();
        if(NativeEndpointDnsMessage.parse(answer(1,new byte[]{127,0,0,1}),"example.com",123,1)!=null)throw new AssertionError();
        System.out.println("Native endpoint DNS wire codec PASS");
    }
}
