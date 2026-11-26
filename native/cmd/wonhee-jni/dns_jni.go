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
 "errors"
 "os"
 "sync"
 "sync/atomic"
 "unsafe"

 quic "github.com/quic-go/quic-go"
 "golang.org/x/sys/unix"
 dualwg "github.com/yooshastan/Wonhee-Proxy/native"
)
type dnsQuicSession struct{
 ctx context.Context
 cancel context.CancelFunc
 roots *x509.CertPool
 endpoint dualwg.DnsEndpoint
 mu sync.Mutex
 client *dualwg.QuicDNSClient
}
var dnsMu sync.Mutex
var dnsNext atomic.Uint64
var quicSessions=map[uint64]*dnsQuicSession{}
var tcpStacks=map[uint64]*dualwg.DnsTCPStack{}

//export WNCreateQuicDns
func WNCreateQuicDns(provider,mode,alternate C.int,roots *C.char,size C.int) C.int64_t{
 if roots==nil||size<1||size>1048576{return -1}
 ep,err:=dualwg.DNSProviderAddress(int(provider),int(mode),int(alternate));if err!=nil{return -1}
 pool:=x509.NewCertPool()
 if !pool.AppendCertsFromPEM(C.GoBytes(unsafe.Pointer(roots),size)){return -1}
 ctx,cancel:=context.WithCancel(context.Background())
 dnsMu.Lock();defer dnsMu.Unlock()
 if len(quicSessions)>=8{cancel();return -1}
 id:=dnsNext.Add(1)
 quicSessions[id]=&dnsQuicSession{ctx:ctx,cancel:cancel,roots:pool,endpoint:ep}
 return C.int64_t(id)
}
//export WNCloseQuicDns
func WNCloseQuicDns(id C.uint64_t){
 dnsMu.Lock();s:=quicSessions[uint64(id)];delete(quicSessions,uint64(id));dnsMu.Unlock()
 if s!=nil{s.cancel();s.mu.Lock();if s.client!=nil{s.client.Close();s.client=nil};s.mu.Unlock()}
}
//export WNExchangeQuicDns
func WNExchangeQuicDns(id C.uint64_t,fd C.int,query *C.char,size C.int,out *C.char,capacity C.int,metrics *C.int64_t) C.int{
 if metrics==nil||fd<0||query==nil||out==nil||size<17||size>dualwg.MaxDnsQuery||capacity<dualwg.MaxDnsReply{return -1}
 dnsMu.Lock();s:=quicSessions[uint64(id)];dnsMu.Unlock()
 if s==nil||s.ctx.Err()!=nil{return -1}
 s.mu.Lock();defer s.mu.Unlock()
 if s.ctx.Err()!=nil{return -1}
 if s.client==nil{
 // Do not close or rebind the Java socket. The duplicated descriptor keeps
 // the existing Android network mark and source port.
 copyFD,err:=unix.FcntlInt(uintptr(fd),unix.F_DUPFD_CLOEXEC,0);if err!=nil{return -1}
 file:=os.NewFile(uintptr(copyFD),"wonhee-vpn-dns");if file==nil{unix.Close(copyFD);return -1}
 pc,err:=net.FilePacketConn(file);file.Close();if err!=nil{return -1}
 keep:=false;defer func(){if !keep{pc.Close()}}()
 udp,ok:=pc.(*net.UDPConn);if !ok{return -1}
 local,ok:=udp.LocalAddr().(*net.UDPAddr)
 if !ok||!local.IP.Equal(net.IPv4(10,253,0,1))||local.Port==0{return -1}
 remote,ok:=udp.RemoteAddr().(*net.UDPAddr)
 if !ok||!remote.IP.Equal(net.ParseIP(s.endpoint.IP))||remote.Port!=s.endpoint.Port{return -1}
 client,err:=dualwg.NewQuicDNSClient(s.ctx,dualwg.ConnectedDNSPacketConn{UDPConn:udp,Peer:remote},s.endpoint,s.roots);if err!=nil{return -2}
 s.client=client;keep=true
 }
 defer func(){stats:=s.client.SocketStats();dst:=unsafe.Slice(metrics,8);for i,v:=range stats{dst[i]=C.int64_t(v)}}()
 response,err:=s.client.Exchange(C.GoBytes(unsafe.Pointer(query),size))
 if err!=nil{if errors.Is(err,dualwg.ErrQuicHandshakeTimeout){return -7};var streamErr *quic.StreamError;var appErr *quic.ApplicationError;var transErr *quic.TransportError;if errors.As(err,&streamErr){return -8};if errors.As(err,&appErr){return -9};if errors.As(err,&transErr){if transErr.ErrorCode>=0x100&&transErr.ErrorCode<=0x1ff{return -11};return -10};if errors.Is(err,dualwg.ErrQuicDNSResponse){return -6};if errors.Is(err,context.DeadlineExceeded){return -3};var ne net.Error;if errors.As(err,&ne)&&ne.Timeout(){return -3};var ce x509.UnknownAuthorityError;var he x509.HostnameError;var ie x509.CertificateInvalidError;if errors.As(err,&ce)||errors.As(err,&he)||errors.As(err,&ie){return -4};return -5}
 if len(response)>int(capacity){return -6}
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
