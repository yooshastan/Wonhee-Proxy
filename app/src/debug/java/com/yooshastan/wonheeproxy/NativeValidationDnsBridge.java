package com.yooshastan.wonheeproxy;

import java.io.*;
import java.net.*;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

/** IPv4 loopback-only validation lab. No protected/direct socket or resolver
 * fallback of its own. Two bounded listeners, fixed names, configured Exit A. */
final class NativeValidationDnsBridge implements AutoCloseable {
    private final ServerSocket tcp;
    private final DatagramSocket udp;
    private final SecureRandom random=new SecureRandom();
    private final Thread udpWorker,tcpWorker;
    private volatile NativeProtectedDnsRelay relay;
    private volatile boolean closed;
    private volatile Socket currentTcp;
    private final AtomicLong requests=new AtomicLong(),refused=new AtomicLong(),answered=new AtomicLong(),failed=new AtomicLong();
    NativeValidationDnsBridge()throws IOException{
        InetAddress loop=InetAddress.getByAddress(new byte[]{127,0,0,1});
        ServerSocket t=new ServerSocket();DatagramSocket u=null;
        try{
            t.bind(new InetSocketAddress(loop,0),4);
            if(t.getLocalPort()<1024)throw new IOException("invalid local port");
            u=new DatagramSocket(null);u.bind(new InetSocketAddress(loop,t.getLocalPort()));
        }catch(IOException|RuntimeException e){try{t.close();}catch(IOException ignored){}if(u!=null)u.close();throw e;}
        tcp=t;udp=u;
        udpWorker=new Thread(this::udpLoop,"WonheeValidationUdp");
        tcpWorker=new Thread(this::tcpLoop,"WonheeValidationTcp");
        udpWorker.start();tcpWorker.start();
    }
    int port(){return tcp.getLocalPort();}
    void setRelay(NativeProtectedDnsRelay next){relay=closed?null:next;}
    String status(){return "IPv4 validation bridge · "+(closed?"closed":relay==null?"waiting/held":"Exit A")+
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
    private void udpLoop(){
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
    private void tcpLoop(){
        while(!closed){
            try(Socket socket=tcp.accept()){
                currentTcp=socket;
                if(closed||!local(socket.getInetAddress())){refused.incrementAndGet();continue;}
                socket.setSoTimeout(2000);
                DataInputStream in=new DataInputStream(socket.getInputStream());
                int n=in.readUnsignedShort();if(n<17||n>NativeProtectedDnsMessage.MAX_DNS){refused.incrementAndGet();continue;}
                byte[] query=new byte[n];in.readFully(query);
                byte[] answer=exchange(query,false);
                if(!closed){DataOutputStream out=new DataOutputStream(socket.getOutputStream());out.writeShort(answer.length);out.write(answer);out.flush();}
            }catch(IOException|RuntimeException e){if(!closed)failed.incrementAndGet();}
            finally{currentTcp=null;}
        }
    }
    @Override public void close(){
        closed=true;relay=null;udp.close();try{tcp.close();}catch(IOException ignored){}
        Socket socket=currentTcp;if(socket!=null)try{socket.close();}catch(IOException ignored){}
        udpWorker.interrupt();tcpWorker.interrupt();
        boolean interrupted=false;
        for(Thread t:new Thread[]{udpWorker,tcpWorker})try{t.join(1000);}catch(InterruptedException e){interrupted=true;}
        if(interrupted)Thread.currentThread().interrupt();
    }
}
