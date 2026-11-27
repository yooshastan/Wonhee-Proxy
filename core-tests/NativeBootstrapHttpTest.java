package com.yooshastan.wonheeproxy;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
public final class NativeBootstrapHttpTest {
    static byte[] bytes(String s){return s.getBytes(StandardCharsets.US_ASCII);}
    static final String HEAD="HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n";
    static byte[] read(String s)throws IOException{return NativeBootstrapHttp.response(new ByteArrayInputStream(bytes(s)));}
    static void reject(String s)throws Exception{try{read(s);throw new AssertionError("accepted invalid HTTP");}catch(IOException expected){}}
    public static void main(String[] args)throws Exception{
        String body="abcdefghijkl";
        if(!Arrays.equals(read(HEAD+"Content-Length: 12\r\n\r\n"+body),bytes(body)))throw new AssertionError();
        if(!Arrays.equals(read(HEAD+"Transfer-Encoding: chunked\r\n\r\n6\r\nabcdef\r\n6\r\nghijkl\r\n0\r\n\r\n"),bytes(body)))throw new AssertionError();
        reject("HTTP/1.1 302 Found\r\nLocation: https://example.com\r\nContent-Length: 12\r\n\r\n"+body);
        reject(HEAD+"Content-Length: 12\r\nContent-Length: 12\r\n\r\n"+body);
        reject(HEAD+"Transfer-Encoding: chunked\r\nContent-Length: 12\r\n\r\n"+body);
        reject(HEAD+"Content-Length: 16385\r\n\r\n");
        reject(HEAD+"Content-Length: 12\r\n\r\nshort");
        reject(HEAD+"Content-Encoding: gzip\r\nContent-Length: 12\r\n\r\n"+body);
        reject("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 12\r\n\r\n"+body);
        reject(HEAD+"Transfer-Encoding: chunked\r\n\r\nffff\r\n");
        ByteArrayOutputStream out=new ByteArrayOutputStream();
        NativeBootstrapHttp.request(out,new byte[12]);
        String request=out.toString("US-ASCII");
        if(!request.startsWith("POST /dns-query HTTP/1.1\r\nHost: cloudflare-dns.com\r\n")||!request.contains("Content-Length: 12\r\n\r\n"))throw new AssertionError();
        out.reset();NativeBootstrapHttp.request(out,new byte[12],"dns.quad9.net");
        if(!out.toString("US-ASCII").contains("Host: dns.quad9.net\r\n"))throw new AssertionError();
        try{NativeBootstrapHttp.request(out,new byte[12],"example.com");throw new AssertionError();}catch(IOException expected){}
        System.out.println("Native bootstrap HTTP checks PASS");
    }
}
