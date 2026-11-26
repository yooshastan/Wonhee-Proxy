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
 "sync"
 "time"

 quic "github.com/quic-go/quic-go"
 "github.com/quic-go/quic-go/http3"
)

const MaxDnsReply=16384
const MaxDnsQuery=1252
var ErrQuicDNSResponse=errors.New("invalid encrypted DNS response")
var ErrQuicHandshakeTimeout=errors.New("QUIC handshake timeout")
func handshakeError(err error)error{if err==nil{return nil};var e net.Error;if errors.Is(err,context.DeadlineExceeded)||errors.As(err,&e)&&e.Timeout(){return ErrQuicHandshakeTimeout};return err}
type DnsEndpoint struct { IP, Host string; Port int; Mode int }
func DNSProvider(provider,mode int)(DnsEndpoint,error){return DNSProviderAddress(provider,mode,0)}
func DNSProviderAddress(provider,mode,alternate int)(DnsEndpoint,error){
 if alternate!=0&&alternate!=1{return DnsEndpoint{},ErrBadArgument}
 pick:=func(a,b string)string{if alternate==1{return b};return a}
 // 1=DoQ; 2=DoH3. Only documented initial provider combinations.
 if mode==1 {
  switch provider {case 1:return DnsEndpoint{pick("9.9.9.9","149.112.112.112"),"dns.quad9.net",853,1},nil
  case 2:return DnsEndpoint{pick("94.140.14.14","94.140.15.15"),"dns.adguard-dns.com",853,1},nil}
 }
 if mode==2 {
  switch provider {case 0:return DnsEndpoint{pick("1.1.1.1","1.0.0.1"),"cloudflare-dns.com",443,2},nil
  case 1:return DnsEndpoint{pick("9.9.9.9","149.112.112.112"),"dns.quad9.net",443,2},nil
  case 2:return DnsEndpoint{pick("94.140.14.14","94.140.15.15"),"dns.adguard-dns.com",443,2},nil}
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

// Socket boundary observations only: no payload or peer identity retained.
type dnsObservedConn struct {
 net.PacketConn
 mu sync.Mutex
 stats [8]int64 // tx count, rx count, tx min/max, rx min/max, write/read errors
}
func(p *dnsObservedConn) record(n int, err error, tx bool) {
 p.mu.Lock();defer p.mu.Unlock()
 i,lo,hi,e:=1,4,5,7
 if tx{i,lo,hi,e=0,2,3,6}
 if err!=nil{p.stats[e]++}
 if n>0{v:=int64(n);p.stats[i]++;if p.stats[lo]==0||v<p.stats[lo]{p.stats[lo]=v};if v>p.stats[hi]{p.stats[hi]=v}}
}
func(p *dnsObservedConn) ReadFrom(b []byte)(int,net.Addr,error){n,a,e:=p.PacketConn.ReadFrom(b);p.record(n,e,false);return n,a,e}
func(p *dnsObservedConn) WriteTo(b []byte,a net.Addr)(int,error){n,e:=p.PacketConn.WriteTo(b,a);p.record(n,e,true);return n,e}
func(p *dnsObservedConn) snapshot()[8]int64{p.mu.Lock();defer p.mu.Unlock();return p.stats}

// QuicDNSClient owns exactly one caller-supplied socket. Exchanges are serialized
// per client; the relay can run four clients concurrently. Never redial a failed
// connection on the same socket, or switch endpoint/transport.
type QuicDNSClient struct {
 pc net.PacketConn
 observed *dnsObservedConn
 ep DnsEndpoint
 addr *net.UDPAddr
 cfg *quic.Config
 tls *tls.Config
 parent context.Context
 stop func() bool
 closeOnce sync.Once
 doq quic.Connection
 h3 *http3.Transport
 httpClient *http.Client
 used bool
}
func NewQuicDNSClient(parent context.Context,pc net.PacketConn,ep DnsEndpoint,roots *x509.CertPool)(*QuicDNSClient,error){
 if pc==nil||roots==nil||ep.Mode!=1&&ep.Mode!=2{return nil,ErrBadArgument}
 ip:=net.ParseIP(ep.IP);if ip==nil||ip.To4()==nil{return nil,ErrBadArgument}
 observed:=&dnsObservedConn{PacketConn:pc};pc=observed
 c:=&QuicDNSClient{pc:pc,observed:observed,ep:ep,addr:&net.UDPAddr{IP:ip.To4(),Port:ep.Port},parent:parent,
 cfg:&quic.Config{HandshakeIdleTimeout:4*time.Second,MaxIdleTimeout:15*time.Second,DisablePathMTUDiscovery:true,InitialPacketSize:1200},
 tls:&tls.Config{ServerName:ep.Host,RootCAs:roots,MinVersion:tls.VersionTLS13}}
 c.stop=context.AfterFunc(parent,func(){_ = pc.Close()})
 if ep.Mode==1 { c.tls.NextProtos=[]string{"doq"} } else {
  c.tls.NextProtos=[]string{http3.NextProtoH3}
  c.h3=&http3.Transport{TLSClientConfig:c.tls,QUICConfig:c.cfg,DisableCompression:true,
   Dial:func(ctx context.Context,destination string,t *tls.Config,q *quic.Config)(quic.EarlyConnection,error){
    if c.used||destination!=net.JoinHostPort(ep.Host,"443"){return nil,errors.New("unexpected HTTP/3 redial")}
    c.used=true
    conn,err:=quic.DialEarly(ctx,boundedPacketConn{pc},c.addr,t,q);if err!=nil{return nil,handshakeError(err)}
    select{case <-conn.HandshakeComplete():return conn,nil
    case <-conn.Context().Done():return nil,handshakeError(context.Cause(conn.Context()))
    case <-ctx.Done():_ = conn.CloseWithError(0,"");return nil,handshakeError(ctx.Err())}
   }}
  c.httpClient=&http.Client{Transport:c.h3,CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}}
 }
 return c,nil
}
func(c *QuicDNSClient) SocketStats()[8]int64{return c.observed.snapshot()}
// Close is called after the owning exchange returns. Parent cancellation wakes IO.
func(c *QuicDNSClient) Close(){
 c.closeOnce.Do(func(){
  c.stop()
  if c.doq!=nil{_ = c.doq.CloseWithError(0,"")}
  if c.h3!=nil{_ = c.h3.Close()}
  _ = c.pc.Close()
 })
}
func(c *QuicDNSClient) Exchange(query []byte)([]byte,error){
 if len(query)<17||len(query)>MaxDnsQuery{return nil,ErrBadArgument}
 ctx,cancel:=context.WithTimeout(c.parent,6*time.Second);defer cancel()
 q:=append([]byte(nil),query...)
 var response []byte
 var err error
 if c.ep.Mode==1{
  q[0],q[1]=0,0
  if c.doq==nil{
   if c.used{return nil,errors.New("unexpected DoQ redial")};c.used=true
   c.doq,err=quic.Dial(ctx,boundedPacketConn{c.pc},c.addr,c.tls,c.cfg)
   if err!=nil{return nil,handshakeError(err)}
  }
  response,err=exchangeDoQStream(ctx,c.doq,q)
 }else{response,err=exchangeH3Request(ctx,c.httpClient,c.ep.Host,q)}
 if err!=nil{return nil,err}
 if len(response)<12||len(response)>MaxDnsReply||!bytes.Equal(response[:2],q[:2]){return nil,ErrQuicDNSResponse}
 response[0],response[1]=query[0],query[1]
 return response,nil
}
func ExchangeQuicDNS(parent context.Context,pc net.PacketConn,ep DnsEndpoint,roots *x509.CertPool,query []byte)([]byte,error){
 if len(query)<17||len(query)>MaxDnsQuery{return nil,ErrBadArgument}
 c,err:=NewQuicDNSClient(parent,pc,ep,roots);if err!=nil{return nil,err};defer c.Close()
 return c.Exchange(query)
}
func exchangeDoQStream(ctx context.Context,conn quic.Connection,q []byte)([]byte,error){
 stream,err:=conn.OpenStreamSync(ctx);if err!=nil{return nil,err}
 stop:=context.AfterFunc(ctx,func(){stream.CancelRead(0);stream.CancelWrite(0)});defer stop()
 deadline,_:=ctx.Deadline();_ = stream.SetDeadline(deadline)
 frame:=make([]byte,2+len(q));binary.BigEndian.PutUint16(frame,uint16(len(q)));copy(frame[2:],q)
 if n,err:=stream.Write(frame);err!=nil{return nil,err}else if n!=len(frame){return nil,io.ErrShortWrite}
 if err=stream.Close();err!=nil{return nil,err}
 var prefix [2]byte
 if _,err=io.ReadFull(stream,prefix[:]);err!=nil{return nil,err}
 size:=int(binary.BigEndian.Uint16(prefix[:]));if size<12||size>MaxDnsReply{return nil,ErrQuicDNSResponse}
 out:=make([]byte,size)
 if _,err=io.ReadFull(stream,out);err!=nil{return nil,err}
 var extra [1]byte
 if n,err:=stream.Read(extra[:]);n!=0{return nil,ErrQuicDNSResponse}else if err!=io.EOF{if err!=nil{return nil,err};return nil,ErrQuicDNSResponse}
 return out,nil
}
func exchangeH3Request(ctx context.Context,client *http.Client,host string,q []byte)([]byte,error){
 req,err:=http.NewRequestWithContext(ctx,http.MethodPost,"https://"+host+"/dns-query",bytes.NewReader(q));if err!=nil{return nil,err}
 req.Header.Set("Content-Type","application/dns-message");req.Header.Set("Accept","application/dns-message");req.Header.Set("Cache-Control","no-store")
 resp,err:=client.Do(req);if err!=nil{return nil,err};defer resp.Body.Close()
 if resp.StatusCode!=200||resp.ProtoMajor!=3||strings.ToLower(strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"),";")[0]))!="application/dns-message"{return nil,ErrQuicDNSResponse}
 body,err:=io.ReadAll(io.LimitReader(resp.Body,MaxDnsReply+1));if err!=nil{return nil,err};if len(body)>MaxDnsReply{return nil,ErrQuicDNSResponse}
 return body,nil
}
