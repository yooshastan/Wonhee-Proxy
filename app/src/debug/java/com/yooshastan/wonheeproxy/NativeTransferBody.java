package com.yooshastan.wonheeproxy;

import java.io.*;
import java.util.Locale;

// Reads only the explicitly requested body; no files, decompression or unbounded buffering.
final class NativeTransferBody {
    interface Progress {void update(int bytes)throws Exception;}
    private static String line(InputStream in)throws IOException{
        StringBuilder s=new StringBuilder();
        while(s.length()<128){
            int b=in.read();if(b<0)throw new EOFException();
            if(b==13){if(in.read()!=10)throw new IOException();return s.toString();}
            if(b<32||b>126)throw new IOException();s.append((char)b);
        }
        throw new IOException();
    }
    static void read(InputStream in,String headers,int expected,Progress progress)throws Exception{
        if(expected<1||expected>2*1024*1024)throw new IOException();
        long length=-1;boolean chunked=false,encoding=false;
        for(String header:headers.split("\\r\\n")){
            int colon=header.indexOf(':');if(colon<0)continue;
            String key=header.substring(0,colon).trim().toLowerCase(Locale.ROOT),value=header.substring(colon+1).trim();
            if(key.equals("content-length")){
                if(length!=-1||!value.matches("[0-9]{1,10}"))throw new IOException();length=Long.parseLong(value);
            }else if(key.equals("transfer-encoding")){
                if(chunked||!value.equalsIgnoreCase("chunked"))throw new IOException();chunked=true;
            }else if(key.equals("content-encoding")){
                if(encoding||!value.equalsIgnoreCase("identity"))throw new IOException();encoding=true;
            }
        }
        if(chunked&&length!=-1||!chunked&&length!=expected)throw new IOException();
        byte[] buffer=new byte[4096];int total=0;
        while(total<expected){
            int part=expected-total;
            if(chunked){
                String size=line(in);
                if(!size.matches("[0-9a-fA-F]{1,8}"))throw new IOException();
                long n=Long.parseLong(size,16);if(n<1||n>part)throw new IOException();part=(int)n;
            }
            while(part>0){
                int got=in.read(buffer,0,Math.min(part,buffer.length));if(got<=0)throw new EOFException();
                part-=got;total+=got;progress.update(total);
            }
            if(chunked&&(in.read()!=13||in.read()!=10))throw new IOException();
        }
        if(chunked&&(!line(in).equals("0")||!line(in).isEmpty()))throw new IOException();
    }
}
