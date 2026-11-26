//go:build android && cgo

package main

/*
#include "jni_bridge.h"
*/
import "C"

import (
 "context"
 "crypto/x509"
 "net"
 "os"
 "sync"
 "sync/atomic"
 "unsafe"

 "golang.org/x/sys/unix"
 dualwg "github.com/yooshastan/Wonhee-Proxy/native"
)
type dnsQuicSession struct{
 ctx context.Context
 cancel context.CancelFunc
 roots *x509.CertPool
 endpoint dualwg.DnsEndpoint
}
var dnsMu sync.Mutex
var dnsNext atomic.Uint64
var quicSessions=map[uint64]*dnsQuicSession{}
var tcpStacks=map[uint64]*dualwg.DnsTCPStack{}

//export WNCreateQuicDns
func WNCreateQuicDns(provider,mode C.int,roots *C.char,size C.int) C.int64_t{
 if roots==nil||size<1||size>1048576{return -1}
 ep,err:=dualwg.DNSProvider(int(provider),int(mode));if err!=nil{return -1}
 pool:=x509.NewCertPool()
 if !pool.AppendCertsFromPEM(C.GoBytes(unsafe.Pointer(roots),size)){return -1}
 ctx,cancel:=context.WithCancel(context.Background())
 dnsMu.Lock();defer dnsMu.Unlock()
 if len(quicSessions)>=2{cancel();return -1}
 id:=dnsNext.Add(1)
 quicSessions[id]=&dnsQuicSession{ctx,cancel,pool,ep}
 return C.int64_t(id)
}
//export WNCloseQuicDns
func WNCloseQuicDns(id C.uint64_t){
 dnsMu.Lock();s:=quicSessions[uint64(id)];delete(quicSessions,uint64(id));dnsMu.Unlock()
 if s!=nil{s.cancel()}
}
//export WNExchangeQuicDns
func WNExchangeQuicDns(id C.uint64_t,fd C.int,query *C.char,size C.int,out *C.char,capacity C.int) C.int{
 if fd<0||query==nil||out==nil||size<17||size>dualwg.MaxDnsQuery||capacity<dualwg.MaxDnsReply{return -1}
 dnsMu.Lock();s:=quicSessions[uint64(id)];dnsMu.Unlock()
 if s==nil||s.ctx.Err()!=nil{return -1}
 // Do not close or rebind the Java socket. The duplicated descriptor keeps
 // the existing Android network mark and source port.
 copyFD,err:=unix.FcntlInt(uintptr(fd),unix.F_DUPFD_CLOEXEC,0);if err!=nil{return -1}
 file:=os.NewFile(uintptr(copyFD),"wonhee-vpn-dns");if file==nil{unix.Close(copyFD);return -1}
 pc,err:=net.FilePacketConn(file);file.Close();if err!=nil{return -1}
 defer pc.Close()
 udp,ok:=pc.(*net.UDPConn);if !ok{return -1}
 local,ok:=udp.LocalAddr().(*net.UDPAddr)
 if !ok||!local.IP.Equal(net.IPv4(10,253,0,1))||local.Port==0{return -1}
 remote,ok:=udp.RemoteAddr().(*net.UDPAddr)
 if !ok||!remote.IP.Equal(net.ParseIP(s.endpoint.IP))||remote.Port!=s.endpoint.Port{return -1}
 response,err:=dualwg.ExchangeQuicDNS(s.ctx,dualwg.ConnectedDNSPacketConn{UDPConn:udp,Peer:remote},s.endpoint,s.roots,C.GoBytes(unsafe.Pointer(query),size))
 if err!=nil||len(response)>int(capacity){return -1}
 copy(unsafe.Slice((*byte)(unsafe.Pointer(out)),int(capacity)),response)
 return C.int(len(response))
}
//export WNCreateDnsTcp
func WNCreateDnsTcp() C.int64_t{
 stack,err:=dualwg.NewDnsTCPStack();if err!=nil{return -1}
 dnsMu.Lock();defer dnsMu.Unlock()
 if len(tcpStacks)>=2{stack.Close();return -1}
 id:=dnsNext.Add(1);tcpStacks[id]=stack;return C.int64_t(id)
}
func tcpStack(id C.uint64_t)*dualwg.DnsTCPStack{dnsMu.Lock();defer dnsMu.Unlock();return tcpStacks[uint64(id)]}
//export WNCloseDnsTcp
func WNCloseDnsTcp(id C.uint64_t){
 dnsMu.Lock();s:=tcpStacks[uint64(id)];delete(tcpStacks,uint64(id));dnsMu.Unlock();if s!=nil{s.Close()}
}
//export WNFeedDnsTcp
func WNFeedDnsTcp(id C.uint64_t,packet *C.char,size C.int) C.int{
 s:=tcpStack(id);if s==nil||packet==nil||size<40||size>1280{return -1}
 if !s.Feed(C.GoBytes(unsafe.Pointer(packet),size)){return -1};return 1
}
//export WNPollDnsTcp
func WNPollDnsTcp(id C.uint64_t,kind C.int,out *C.char,capacity C.int) C.int{
 s:=tcpStack(id);if s==nil||out==nil||capacity<1280||capacity>32768{return -1}
 var b []byte
 if kind==0{b=s.PollPacket()}else if kind==1{b=s.PollQuery()}else{return -1}
 if len(b)>int(capacity){return -1}
 copy(unsafe.Slice((*byte)(unsafe.Pointer(out)),int(capacity)),b);return C.int(len(b))
}
//export WNAnswerDnsTcp
func WNAnswerDnsTcp(id C.uint64_t,token C.uint64_t,answer *C.char,size C.int) C.int{
 s:=tcpStack(id);if s==nil||answer==nil||size<12||size>dualwg.MaxDnsReply{return -1}
 if s.Answer(uint64(token),C.GoBytes(unsafe.Pointer(answer),size)){return 1};return -1
}
