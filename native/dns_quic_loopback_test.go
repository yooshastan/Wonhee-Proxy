package dualwg

import (
 "context"
 "crypto/ecdsa"
 "crypto/elliptic"
 "crypto/rand"
 "crypto/tls"
 "crypto/x509"
 "crypto/x509/pkix"
 "encoding/binary"
 "io"
 "math/big"
 "net"
 "net/http"
 "testing"
 "time"

 quic "github.com/quic-go/quic-go"
 "github.com/quic-go/quic-go/http3"
)
func testDnsCertificate(t *testing.T)(tls.Certificate,*x509.CertPool){
 t.Helper()
 key,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if err!=nil{t.Fatal(err)}
 template:=&x509.Certificate{SerialNumber:big.NewInt(1),Subject:pkix.Name{CommonName:"dns.test"},DNSNames:[]string{"dns.test"},NotBefore:time.Now().Add(-time.Hour),NotAfter:time.Now().Add(time.Hour),KeyUsage:x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign,ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},BasicConstraintsValid:true,IsCA:true}
 der,err:=x509.CreateCertificate(rand.Reader,template,template,&key.PublicKey,key);if err!=nil{t.Fatal(err)}
 cert,err:=x509.ParseCertificate(der);if err!=nil{t.Fatal(err)}
 roots:=x509.NewCertPool();roots.AddCert(cert)
 return tls.Certificate{Certificate:[][]byte{der},PrivateKey:key},roots
}
func testQuestion()[]byte{return []byte{0x12,0x34,1,0,0,1,0,0,0,0,0,0,1,'a',0,0,1,0,1}}
func TestDoQAuthenticatedLoopback(t *testing.T){
 cert,roots:=testDnsCertificate(t)
 listener,err:=quic.ListenAddr("127.0.0.1:0",&tls.Config{Certificates:[]tls.Certificate{cert},NextProtos:[]string{"doq"}},nil);if err!=nil{t.Fatal(err)}
 defer listener.Close()
 ctx,cancel:=context.WithTimeout(context.Background(),6*time.Second);defer cancel()
 server:=make(chan error,1)
 go func(){
  c,e:=listener.Accept(ctx);if e!=nil{server<-e;return}
  for i:=0;i<2;i++{
  stream,e:=c.AcceptStream(ctx);if e!=nil{server<-e;return}
  var p [2]byte;if _,e=io.ReadFull(stream,p[:]);e!=nil{server<-e;return}
  q:=make([]byte,int(binary.BigEndian.Uint16(p[:])));if _,e=io.ReadFull(stream,q);e!=nil{server<-e;return}
  if q[0]!=0||q[1]!=0{server<-ErrBadArgument;return}
  q[2]=0x81
  frame:=append(p[:],q...);_,e=stream.Write(frame);if e==nil{e=stream.Close()};if e!=nil{server<-e;return}
  }
  server<-nil
 }()
 pc,err:=net.ListenPacket("udp4","127.0.0.1:0");if err!=nil{t.Fatal(err)};defer pc.Close()
 ep:=DnsEndpoint{"127.0.0.1","dns.test",listener.Addr().(*net.UDPAddr).Port,1}
 client,err:=NewQuicDNSClient(ctx,pc,ep,roots);if err!=nil{t.Fatal(err)};defer client.Close()
 for i:=0;i<2;i++{
  q:=testQuestion();q[1]=byte(0x34+i)
  a,err:=client.Exchange(q)
  if err!=nil||len(a)!=len(q)||a[0]!=q[0]||a[1]!=q[1]||a[2]!=0x81{t.Fatalf("DoQ reused response %d: %v",i,err)}
 }
 if e:=<-server;e!=nil{t.Fatal(e)}
 stats:=client.SocketStats();if stats[0]==0||stats[1]==0||stats[2]==0||stats[3]<stats[2]||stats[4]==0||stats[5]<stats[4]{t.Fatalf("invalid socket observations %v",stats)}
}
func TestHTTP3AuthenticatedLoopback(t *testing.T){
 cert,roots:=testDnsCertificate(t)
 socket,err:=net.ListenPacket("udp4","127.0.0.1:0");if err!=nil{t.Fatal(err)};defer socket.Close()
 server:=&http3.Server{TLSConfig:&tls.Config{Certificates:[]tls.Certificate{cert},NextProtos:[]string{http3.NextProtoH3}},Handler:http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  if r.ProtoMajor!=3||r.Method!="POST"||r.URL.Path!="/dns-query"||r.Header.Get("Content-Type")!="application/dns-message"{w.WriteHeader(400);return}
  q,e:=io.ReadAll(io.LimitReader(r.Body,MaxDnsQuery+1));if e!=nil||len(q)!=len(testQuestion()){w.WriteHeader(400);return}
  q[2]=0x81;w.Header().Set("Content-Type","application/dns-message");w.Write(q)
 })}
 defer server.Close()
 go server.Serve(socket)
 ctx,cancel:=context.WithTimeout(context.Background(),6*time.Second);defer cancel()
 pc,err:=net.ListenPacket("udp4","127.0.0.1:0");if err!=nil{t.Fatal(err)};defer pc.Close()
 ep:=DnsEndpoint{"127.0.0.1","dns.test",socket.LocalAddr().(*net.UDPAddr).Port,2}
 client,err:=NewQuicDNSClient(ctx,pc,ep,roots);if err!=nil{t.Fatal(err)};defer client.Close()
 for i:=0;i<2;i++{
  q:=testQuestion();q[1]=byte(0x34+i)
  a,err:=client.Exchange(q)
  if err!=nil||len(a)!=len(q)||a[0]!=q[0]||a[1]!=q[1]||a[2]!=0x81{t.Fatalf("HTTP/3 reused response %d: %v",i,err)}
 }
}
