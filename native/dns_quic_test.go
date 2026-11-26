package dualwg

import (
 "context"
 "crypto/x509"
 "net"
 "testing"
)
func TestDNSProviderMatrix(t *testing.T){
 for p:=0;p<4;p++{for m:=1;m<=2;m++{
  _,err:=DNSProvider(p,m);want:=m==1&&(p==1||p==2)||m==2&&(p==0||p==1)
  if (err==nil)!=want{t.Fatalf("provider %d mode %d",p,m)}
 }}
}
type noNetwork struct{net.PacketConn;writes int}
func (p *noNetwork) WriteTo(b []byte,a net.Addr)(int,error){p.writes++;return len(b),nil}
func TestQuicBounds(t *testing.T){
 p:=&noNetwork{}
 if _,err:=(boundedPacketConn{p}).WriteTo(make([]byte,1253),nil);err==nil||p.writes!=0{t.Fatal("oversize datagram transmitted")}
 if _,err:=(boundedPacketConn{p}).WriteTo(make([]byte,1200),nil);err!=nil||p.writes!=1{t.Fatal("valid size refused")}
 if _,err:=ExchangeQuicDNS(context.Background(),p,DnsEndpoint{},x509.NewCertPool(),make([]byte,16));err==nil{t.Fatal("invalid query accepted")}
}
