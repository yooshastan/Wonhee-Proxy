package dualwg
import("testing";"time";"net/netip";"encoding/binary";"crypto/ecdh";"crypto/rand";"encoding/base64";"strings")
func routePacket(remote [4]byte,proto byte,reply,syn bool)[]byte{
 n:=28;if proto==6{n=40}
 p:=make([]byte,n);p[0]=0x45;p[9]=proto;binary.BigEndian.PutUint16(p[2:4],uint16(n))
 copy(p[12:16],[]byte{10,1,2,3});copy(p[16:20],remote[:]);binary.BigEndian.PutUint16(p[20:22],40000);binary.BigEndian.PutUint16(p[22:24],443)
 if proto==6{p[32]=0x50;p[33]=16;if syn{p[33]=2}}else{binary.BigEndian.PutUint16(p[24:26],8)}
 if reply{copy(p[12:16],remote[:]);copy(p[16:20],[]byte{10,1,2,3});binary.BigEndian.PutUint16(p[20:22],443);binary.BigEndian.PutUint16(p[22:24],40000)}
 return p
}
func TestRouteScopeLedger(t *testing.T){
 s:=&RouteScope{local:netip.MustParseAddr("10.1.2.3"),flows:make(map[RouteTuple]time.Time)}
 now:=time.Now();remote:=[4]byte{1,1,1,1}
 if s.incoming(routePacket(remote,6,true,false),now)||s.outgoing(routePacket(remote,6,false,false),now){t.Fatal("unsolicited TCP")}
 if !s.outgoing(routePacket(remote,6,false,true),now)||!s.incoming(routePacket(remote,6,true,false),now){t.Fatal("TCP ownership")}
 if s.incoming(routePacket(remote,17,true,false),now)||s.incoming(routePacket([4]byte{1,0,0,1},6,true,false),now){t.Fatal("foreign tuple")}
 if !s.outgoing(routePacket(remote,17,false,false),now)||!s.incoming(routePacket(remote,17,true,false),now){t.Fatal("UDP ownership")}
 if s.incoming(routePacket(remote,17,true,false),now.Add(61*time.Second)){t.Fatal("UDP expiry")}
 if s.outgoing(routePacket([4]byte{10,0,0,1},6,false,true),now){t.Fatal("private through exit")}
 if s.incoming(routePacket(remote,6,true,false),now.Add(301*time.Second)){t.Fatal("TCP expiry")}
 home:=&RouteScope{local:s.local,isHome:true,home:netip.MustParsePrefix("10.0.0.0/24"),flows:make(map[RouteTuple]time.Time)}
 if !home.outgoing(routePacket([4]byte{10,0,0,169},6,false,true),now)||home.outgoing(routePacket(remote,6,false,true),now){t.Fatal("Home scope")}
}
func TestRouteScopeAllowedIPs(t *testing.T){
 a,_:=ecdh.X25519().GenerateKey(rand.Reader);b,_:=ecdh.X25519().GenerateKey(rand.Reader);enc:=base64.StdEncoding.EncodeToString
 cfg:="[Interface]\nPrivateKey = "+enc(a.Bytes())+"\n[Peer]\nPublicKey = "+enc(b.PublicKey().Bytes())+"\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 192.0.2.1:1637\n"
 if _,ipc,e:=NewRouteScope("exit-a",cfg,"10.1.2.3","");e!=nil||!strings.Contains(ipc,"allowed_ip=0.0.0.0/0"){t.Fatal("exit config")}
 if _,ipc,e:=NewRouteScope("home",cfg,"10.1.2.3","10.0.0.0/24");e!=nil||!strings.Contains(ipc,"allowed_ip=10.0.0.0/24")||strings.Contains(ipc,"allowed_ip=0.0.0.0/0"){t.Fatal("home narrowing")}
 limited:=strings.Replace(cfg,"0.0.0.0/0","10.0.0.0/24",1)
 if _,_,e:=NewRouteScope("exit-a",limited,"10.1.2.3","");e==nil{t.Fatal("expanded provider permission")}
 if _,_,e:=NewRouteScope("home",limited,"10.1.2.3","10.0.0.0/16");e==nil{t.Fatal("expanded home permission")}
}
