package dualwg
import (
 "context"
 "encoding/binary"
 "io"
 "net"
 "net/netip"
 "testing"
 "time"
 "golang.zx2c4.com/wireguard/tun/netstack"
)
func TestLocalTCPDNS(t *testing.T){
 s,err:=NewDnsTCPStack();if err!=nil{t.Fatal(err)};defer s.Close()
 client,network,err:=netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.253.0.1")},nil,1280)
 if err!=nil{t.Fatal(err)};defer client.Close()
 done:=make(chan struct{});defer close(done)
 go func(){b:=make([]byte,1280);sizes:=make([]int,1);for{n,e:=client.Read([][]byte{b},sizes,0);if e!=nil{return};if n==1{s.Feed(b[:sizes[0]])}}}()
 go func(){tick:=time.NewTicker(time.Millisecond);defer tick.Stop();for{select{case <-done:return;case <-tick.C:for{p:=s.PollPacket();if p==nil{break};_,_=client.Write([][]byte{p},0)}}}}()
 go func(){tick:=time.NewTicker(time.Millisecond);defer tick.Stop();for{select{case <-done:return;case <-tick.C:if q:=s.PollQuery();q!=nil{a:=make([]byte,2400);copy(a,q[8:]);a[2]=0x81;s.Answer(binary.BigEndian.Uint64(q),a)}}}}()
 ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second);defer cancel()
 c,err:=network.DialContextTCP(ctx,&net.TCPAddr{IP:net.IP{1,1,1,1},Port:53});if err!=nil{t.Fatal(err)};defer c.Close()
 c.SetDeadline(time.Now().Add(5*time.Second))
 q:=make([]byte,19);q[0]=0x12;q[1]=0x34
 frame:=make([]byte,2+len(q));binary.BigEndian.PutUint16(frame,uint16(len(q)));copy(frame[2:],q)
 if _,err=c.Write(frame[:5]);err!=nil{t.Fatal(err)};if _,err=c.Write(frame[5:]);err!=nil{t.Fatal(err)}
 var size [2]byte;if _,err=io.ReadFull(c,size[:]);err!=nil{t.Fatal(err)}
 if binary.BigEndian.Uint16(size[:])!=2400{t.Fatal("large TCP reply lost")}
 a:=make([]byte,2400);if _,err=io.ReadFull(c,a);err!=nil||a[0]!=0x12||a[1]!=0x34{t.Fatal("bad TCP reply",err)}
 if s.Feed(make([]byte,40)){t.Fatal("malformed packet accepted")}
}
