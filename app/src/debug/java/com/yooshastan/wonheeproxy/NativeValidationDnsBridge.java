package com.yooshastan.wonheeproxy;

import java.io.*;
import java.net.*;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

/** Dual-stack loopback-only validation lab. No direct socket fallback. */
final class NativeValidationDnsBridge implements AutoCloseable {
    private final ServerSocket tcp,tcp6;
    private final DatagramSocket udp,udp6;
    private final SecureRandom random=new SecureRandom();
    private final Thread udpWorker,tcpWorker,udpWorker6,tcpWorker6;
    private volatile NativeProtectedDnsRelay relay;
    private volatile boolean closed;
    private volatile Socket currentTcp,currentTcp6;
    private final AtomicLong requests=new AtomicLong(),refused=new AtomicLong(),answered=new AtomicLong(),failed=new AtomicLong();
    private final boolean dual;
    NativeValidationDnsBridge(boolean dual)throws IOException{
        this.dual=dual;
        InetAddress loop=InetAddress.getByAddress(new byte[]{127,0,0,1});
        InetAddress loop6=InetAddress.getByAddress(new byte[]{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1});
        ServerSocket t=new ServerSocket(),t6=null;DatagramSocket u=null,u6=null;
        try{
            t.bind(new InetSocketAddress(loop,0),4);
            if(t.getLocalPort()<1024)throw new IOException("invalid local port");
            u=new DatagramSocket(null);u.bind(new InetSocketAddress(loop,t.getLocalPort()));
            if(dual){t6=new ServerSocket();t6.bind(new InetSocketAddress(loop6,t.getLocalPort()),4);
                u6=new DatagramSocket(null);u6.bind(new InetSocketAddress(loop6,t.getLocalPort()));}
        }catch(IOException|RuntimeException e){try{t.close();}catch(IOException ignored){}if(u!=null)u.close();if(t6!=null)try{t6.close();}catch(IOException ignored){}if(u6!=null)u6.close();throw e;}
        tcp=t;udp=u;tcp6=t6;udp6=u6;
        udpWorker=new Thread(()->udpLoop(udp),"WonheeValidationUdp4");
        tcpWorker=new Thread(()->tcpLoop(tcp,false),"WonheeValidationTcp4");
        udpWorker6=dual?new Thread(()->udpLoop(udp6),"WonheeValidationUdp6"):null;
        tcpWorker6=dual?new Thread(()->tcpLoop(tcp6,true),"WonheeValidationTcp6"):null;
        udpWorker.start();tcpWorker.start();if(dual){udpWorker6.start();tcpWorker6.start();}
    }
    int port(){return tcp.getLocalPort();}
    void setRelay(NativeProtectedDnsRelay next){relay=closed?null:next;}
    String status(){return (dual?"Dual-stack validation bridge · ":"IPv4 root validation bridge · IPv6 NAT unavailable/unverified · ")+(closed?"closed":relay==null?"waiting/held":"Exit A")+
        " requests="+requests.get()+" answered="+answered.get()+" refused="+refused.get()+" failed="+failed.get();}
    private boolean local(InetAddress address){
        try{return address.isLoopbackAddress()||NetworkInterface.getByInetAddress(address)!=null;}
        catch(SocketException e){return false;}
    }
    private byte[] exchange(byte[] query,boolean datagram)throws IOException{
        requests.incrementAndGet();
        final byte[] canonical;
        try{canonical=NativeValidationDnsPolicy.canonical(query,random.nextInt(65536));}
        catch(IOException|RuntimeException e){
            refused.incrementAndGet();
            return NativeProtectedDnsMessage.error(query,5,false);
        }
        NativeProtectedDnsRelay active=relay;
        if(closed||active==null||active.role!=0){failed.incrementAndGet();return NativeProtectedDnsMessage.error(query,2,false);}
        CompletableFuture<byte[]> result=new CompletableFuture<>();
        active.resolveValidation(canonical,result::complete);
        try{
            byte[] response=result.get(3500,TimeUnit.MILLISECONDS);
            if(closed||relay!=active)throw new IOException("validation relay changed");
            byte[] answer=NativeValidationDnsPolicy.response(query,canonical,response,datagram);
            if((NativeProtectedDnsMessage.u16(answer,2)&15)==0)answered.incrementAndGet();else failed.incrementAndGet();
            return answer;
        }catch(Exception e){
            failed.incrementAndGet();
            if(e instanceof InterruptedException)Thread.currentThread().interrupt();
            return NativeProtectedDnsMessage.error(query,2,false);
        }finally{result.cancel(false);}
    }
    private void udpLoop(DatagramSocket udp){
        byte[] buffer=new byte[NativeProtectedDnsMessage.MAX_DNS+1];
        while(!closed){
            try{
                DatagramPacket packet=new DatagramPacket(buffer,buffer.length);udp.receive(packet);
                if(!local(packet.getAddress())||packet.getLength()>NativeProtectedDnsMessage.MAX_DNS){refused.incrementAndGet();continue;}
                byte[] answer=exchange(Arrays.copyOfRange(packet.getData(),packet.getOffset(),packet.getOffset()+packet.getLength()),true);
                if(!closed)udp.send(new DatagramPacket(answer,answer.length,packet.getAddress(),packet.getPort()));
            }catch(IOException|RuntimeException e){if(!closed)failed.incrementAndGet();}
        }
    }
    private void tcpLoop(ServerSocket tcp,boolean ipv6){
        while(!closed){
            try(Socket socket=tcp.accept()){
                if(ipv6)currentTcp6=socket;else currentTcp=socket;
                if(closed||!local(socket.getInetAddress())){refused.incrementAndGet();continue;}
                socket.setSoTimeout(2000);
                DataInputStream in=new DataInputStream(socket.getInputStream());
                int n=in.readUnsignedShort();if(n<17||n>NativeProtectedDnsMessage.MAX_DNS){refused.incrementAndGet();continue;}
                byte[] query=new byte[n];in.readFully(query);
                byte[] answer=exchange(query,false);
                if(!closed){DataOutputStream out=new DataOutputStream(socket.getOutputStream());out.writeShort(answer.length);out.write(answer);out.flush();}
            }catch(IOException|RuntimeException e){if(!closed)failed.incrementAndGet();}
            finally{if(ipv6)currentTcp6=null;else currentTcp=null;}
        }
    }
    @Override public void close(){
        closed=true;relay=null;udp.close();if(udp6!=null)udp6.close();
        for(ServerSocket listener:new ServerSocket[]{tcp,tcp6})if(listener!=null)try{listener.close();}catch(IOException ignored){}
        for(Socket socket:new Socket[]{currentTcp,currentTcp6})if(socket!=null)try{socket.close();}catch(IOException ignored){}
        for(Thread t:new Thread[]{udpWorker,tcpWorker,udpWorker6,tcpWorker6})if(t!=null)t.interrupt();
        boolean interrupted=false;
        for(Thread t:new Thread[]{udpWorker,tcpWorker,udpWorker6,tcpWorker6})if(t!=null)try{t.join(1000);}catch(InterruptedException e){interrupted=true;}
        if(interrupted)Thread.currentThread().interrupt();
    }
}
