package com.yooshastan.wonheeproxy;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

// Strict bounded HTTP/1.1 framing for a single authenticated DNS wire response.
final class NativeBootstrapHttp {
    private static final int MAX_BODY=16384,MAX_HEADERS=16384;
    static void request(OutputStream out,byte[] query)throws IOException{
        request(out,query,"cloudflare-dns.com");
    }
    static void request(OutputStream out,byte[] query,String host)throws IOException{
        if(!host.equals("cloudflare-dns.com")&&!host.equals("dns.quad9.net")&&!host.equals("dns.adguard-dns.com"))throw new IOException();
        if(query.length<12||query.length>512)throw new IOException();
        String headers="POST /dns-query HTTP/1.1\r\nHost: "+host+"\r\nAccept: application/dns-message\r\nContent-Type: application/dns-message\r\nAccept-Encoding: identity\r\nConnection: close\r\nContent-Length: "+query.length+"\r\n\r\n";
        out.write(headers.getBytes(StandardCharsets.US_ASCII));out.write(query);out.flush();
    }
    private static String line(InputStream in,int[] budget)throws IOException{
        StringBuilder s=new StringBuilder();
        while(budget[0]-->0){
            int b=in.read();if(b<0)throw new EOFException();
            if(b==13){if(budget[0]--<=0||in.read()!=10)throw new IOException();return s.toString();}
            if(b<32||b>126||s.length()>=4096)throw new IOException();
            s.append((char)b);
        }
        throw new IOException();
    }
    private static void copy(InputStream in,ByteArrayOutputStream out,int n)throws IOException{
        if(n<0||n>MAX_BODY-out.size())throw new IOException();
        byte[] buffer=new byte[1024];
        while(n>0){int got=in.read(buffer,0,Math.min(n,buffer.length));if(got<=0)throw new EOFException();out.write(buffer,0,got);n-=got;}
    }
    static byte[] response(InputStream in)throws IOException{
        int[] budget={MAX_HEADERS};
        if(!line(in,budget).matches("HTTP/1\\.[01] 200(?: .*)?"))throw new IOException();
        int length=-1;boolean chunked=false,type=false,encoding=false;
        for(String h;!(h=line(in,budget)).isEmpty();){
            int colon=h.indexOf(':');
            if(colon<1||!h.substring(0,colon).matches("[!#$%&'*+.^_\\x60|~0-9A-Za-z-]+"))throw new IOException();
            String key=h.substring(0,colon).toLowerCase(Locale.ROOT),value=h.substring(colon+1).trim();
            switch(key){
                case "content-type":
                    if(type||!value.equalsIgnoreCase("application/dns-message"))throw new IOException();type=true;break;
                case "content-length":
                    if(length!=-1||!value.matches("[0-9]{1,5}"))throw new IOException();
                    length=Integer.parseInt(value);if(length<12||length>MAX_BODY)throw new IOException();break;
                case "transfer-encoding":
                    if(chunked||!value.equalsIgnoreCase("chunked"))throw new IOException();chunked=true;break;
                case "content-encoding":
                    if(encoding||!value.equalsIgnoreCase("identity"))throw new IOException();encoding=true;break;
            }
        }
        if(!type||chunked==(length!=-1))throw new IOException();
        ByteArrayOutputStream out=new ByteArrayOutputStream();
        if(!chunked)copy(in,out,length);
        else{
            for(;;){
                String size=line(in,budget);
                if(!size.matches("[0-9a-fA-F]{1,4}"))throw new IOException();
                int n=Integer.parseInt(size,16);
                if(n==0){if(!line(in,budget).isEmpty())throw new IOException();break;}
                copy(in,out,n);
                if(in.read()!=13||in.read()!=10)throw new IOException();
            }
        }
        if(out.size()<12)throw new IOException();
        return out.toByteArray();
    }
    private NativeBootstrapHttp(){}
}
