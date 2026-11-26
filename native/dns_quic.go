package dualwg

import (
 "bytes"
 "context"
 "crypto/tls"
 "crypto/x509"
 "encoding/binary"
 "errors"
 "io"
 "net"
 "net/http"
 "strings"
 "time"

 quic "github.com/quic-go/quic-go"
 "github.com/quic-go/quic-go/http3"
)

const MaxDnsReply=16384
const MaxDnsQuery=1252
type DnsEndpoint struct { IP, Host string; Port int; Mode int }
func DNSProvider(provider,mode int)(DnsEndpoint,error){
 // 1=DoQ; 2=DoH3. Only documented initial provider combinations.
 if mode==1 {
  switch provider {case 1:return DnsEndpoint{"9.9.9.9","dns.quad9.net",853,1},nil
  case 2:return DnsEndpoint{"94.140.14.14","dns.adguard-dns.com",853,1},nil}
 }
 if mode==2 {
  switch provider {case 0:return DnsEndpoint{"1.1.1.1","cloudflare-dns.com",443,2},nil
  case 1:return DnsEndpoint{"9.9.9.9","dns.quad9.net",443,2},nil}
 }
 return DnsEndpoint{},errors.New("unsupported encrypted DNS provider")
}

// Hide UDPConn-specific GSO / PMTU features. Only the caller's already-bound
// packet socket can transmit; no DNS lookup, no system dialer, no fallback.
type boundedPacketConn struct{ net.PacketConn }
// A connected UDP descriptor is required for Android connection-owner lookup.
// quic-go uses PacketConn.WriteTo, so adapt it to the connected socket without
// permitting any destination change (including server migration).
type ConnectedDNSPacketConn struct{ *net.UDPConn; Peer *net.UDPAddr }
func (p ConnectedDNSPacketConn) WriteTo(b []byte,a net.Addr)(int,error){
 dst,ok:=a.(*net.UDPAddr)
 if !ok||!dst.IP.Equal(p.Peer.IP)||dst.Port!=p.Peer.Port{return 0,errors.New("unexpected QUIC destination")}
 return p.UDPConn.Write(b)
}
func (p boundedPacketConn) WriteTo(b []byte,a net.Addr)(int,error){
 if len(b)>1252{return 0,errors.New("QUIC datagram exceeds TUN MTU")}
 return p.PacketConn.WriteTo(b,a)
}

func ExchangeQuicDNS(parent context.Context,pc net.PacketConn,ep DnsEndpoint,roots *x509.CertPool,query []byte)([]byte,error){
 if pc==nil||roots==nil||len(query)<17||len(query)>MaxDnsQuery{return nil,ErrBadArgument}
 if ep.Mode!=1&&ep.Mode!=2{return nil,ErrBadArgument}
 ip:=net.ParseIP(ep.IP);if ip==nil||ip.To4()==nil{return nil,ErrBadArgument}
 ctx,cancel:=context.WithTimeout(parent,10*time.Second);defer cancel()
 // Closing the caller-owned duplicate wakes any socket reads on cancellation.
 stop:=context.AfterFunc(ctx,func(){_ = pc.Close()});defer stop()
 socket:=boundedPacketConn{pc}
 addr:=&net.UDPAddr{IP:ip.To4(),Port:ep.Port}
 cfg:=&quic.Config{HandshakeIdleTimeout:4*time.Second,MaxIdleTimeout:5*time.Second,DisablePathMTUDiscovery:true,InitialPacketSize:1200}
 tlsCfg:=&tls.Config{ServerName:ep.Host,RootCAs:roots,MinVersion:tls.VersionTLS13}
 q:=append([]byte(nil),query...)
 var response []byte
 var err error
 if ep.Mode==1{
  q[0],q[1]=0,0
  tlsCfg.NextProtos=[]string{"doq"}
  response,err=exchangeDoQ(ctx,socket,addr,tlsCfg,cfg,q)
 }else{
  tlsCfg.NextProtos=[]string{http3.NextProtoH3}
  response,err=exchangeH3(ctx,socket,addr,tlsCfg,cfg,ep.Host,q)
 }
 if err!=nil{return nil,err}
 if len(response)<12||len(response)>MaxDnsReply||!bytes.Equal(response[:2],q[:2]){return nil,errors.New("DNS response ID or size")}
 // DoQ requires ID zero on the wire; restore only after verifying zero.
 response[0],response[1]=query[0],query[1]
 return response,nil
}
func exchangeDoQ(ctx context.Context,pc net.PacketConn,addr net.Addr,tlsCfg *tls.Config,cfg *quic.Config,q []byte)([]byte,error){
 conn,err:=quic.Dial(ctx,pc,addr,tlsCfg,cfg);if err!=nil{return nil,err}
 defer conn.CloseWithError(0,"")
 stream,err:=conn.OpenStreamSync(ctx);if err!=nil{return nil,err}
 deadline,_:=ctx.Deadline();_ = stream.SetDeadline(deadline)
 frame:=make([]byte,2+len(q));binary.BigEndian.PutUint16(frame,uint16(len(q)));copy(frame[2:],q)
 if n,err:=stream.Write(frame);err!=nil||n!=len(frame){return nil,errors.New("DoQ write")}
 if err=stream.Close();err!=nil{return nil,err}
 var prefix [2]byte
 if _,err=io.ReadFull(stream,prefix[:]);err!=nil{return nil,err}
 size:=int(binary.BigEndian.Uint16(prefix[:]));if size<12||size>MaxDnsReply{return nil,errors.New("DoQ size")}
 out:=make([]byte,size)
 if _,err=io.ReadFull(stream,out);err!=nil{return nil,err}
 var extra [1]byte
 if n,err:=stream.Read(extra[:]);n!=0||err!=io.EOF{return nil,errors.New("DoQ extra response")}
 return out,nil
}
func exchangeH3(ctx context.Context,pc net.PacketConn,addr net.Addr,tlsCfg *tls.Config,cfg *quic.Config,host string,q []byte)([]byte,error){
 // No alternate endpoints, redirects, HTTP/2 fallback or early DNS request.
 used:=false
 transport:=&http3.Transport{TLSClientConfig:tlsCfg,QUICConfig:cfg,DisableCompression:true,
  Dial:func(ctx context.Context,destination string,t *tls.Config,c *quic.Config)(quic.EarlyConnection,error){
   if used||destination!=net.JoinHostPort(host,"443"){return nil,errors.New("unexpected HTTP/3 dial")}
   used=true
   conn,err:=quic.DialEarly(ctx,pc,addr,t,c);if err!=nil{return nil,err}
   select{case <-conn.HandshakeComplete():return conn,nil
   case <-conn.Context().Done():return nil,conn.Context().Err()
   case <-ctx.Done():_ = conn.CloseWithError(0,"");return nil,ctx.Err()}
  }}
 defer transport.Close()
 client:=&http.Client{Transport:transport,CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}}
 req,err:=http.NewRequestWithContext(ctx,http.MethodPost,"https://"+host+"/dns-query",bytes.NewReader(q));if err!=nil{return nil,err}
 req.Header.Set("Content-Type","application/dns-message");req.Header.Set("Accept","application/dns-message");req.Header.Set("Cache-Control","no-store")
 resp,err:=client.Do(req);if err!=nil{return nil,err};defer resp.Body.Close()
 if resp.StatusCode!=200||resp.ProtoMajor!=3||strings.ToLower(strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"),";")[0]))!="application/dns-message"{return nil,errors.New("HTTP/3 DNS response")}
 body,err:=io.ReadAll(io.LimitReader(resp.Body,MaxDnsReply+1));if err!=nil||len(body)>MaxDnsReply{return nil,errors.New("HTTP/3 DNS body")}
 return body,nil
}
