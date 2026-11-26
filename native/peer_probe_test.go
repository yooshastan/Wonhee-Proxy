package dualwg
import("crypto/ecdh";"crypto/rand";"encoding/base64";"encoding/binary";"strings";"testing")
func TestProbeScope(t *testing.T){
 s,e:=NewProbeScope("exit-a","10.1.2.3","1.1.1.1",443);if e!=nil{t.Fatal(e)}
 p:=make([]byte,40);p[0]=0x45;p[9]=6;p[32]=0x50
 binary.BigEndian.PutUint16(p[2:4],40);copy(p[12:16],[]byte{10,1,2,3});copy(p[16:20],[]byte{1,1,1,1})
 binary.BigEndian.PutUint16(p[20:22],40000);binary.BigEndian.PutUint16(p[22:24],443)
 if !s.Match(p,false)||s.Match(p,true){t.Fatal("outbound scope")}
 q:=append([]byte(nil),p...);copy(q[12:16],p[16:20]);copy(q[16:20],p[12:16]);copy(q[20:22],p[22:24]);copy(q[22:24],p[20:22])
 if !s.Match(q,true)||s.Match(q,false){t.Fatal("reply scope")}
 q[12]=9;if s.Match(q,true){t.Fatal("foreign peer reply")}
 p=append(p,1);binary.BigEndian.PutUint16(p[2:4],41);if !s.Match(p,false){t.Fatal("scoped payload rejected")}
 if !ProbePort(p,false,[2]uint16{40000,40001})||ProbePort(p,false,[2]uint16{40002,40003})||ProbePort(p,false,[2]uint16{}){t.Fatal("port ownership")}
 if ProbePort(q,true,[2]uint16{40002,40003})||!ProbePort(q,true,[2]uint16{40000,40001}){t.Fatal("reply port ownership")}
 p[32]=0xf0;if s.Match(p,false){t.Fatal("truncated TCP header")}
 if _,e:=NewProbeScope("exit-b","10.1.2.3","1.1.1.1",443);e==nil{t.Fatal("cross exit")}
 if _,e:=NewProbeScope("home","10.1.2.3","1.1.1.1",443);e==nil{t.Fatal("public home target")}
 a,_:=ecdh.X25519().GenerateKey(rand.Reader);b,_:=ecdh.X25519().GenerateKey(rand.Reader);enc:=base64.StdEncoding.EncodeToString
 config:="[Interface]\nPrivateKey = "+enc(a.Bytes())+"\n[Peer]\nPublicKey = "+enc(b.PublicKey().Bytes())+"\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 192.0.2.1:1637\n"
 ipc,e:=PeerProbeConfig(config,s);if e!=nil || !strings.Contains(ipc,"allowed_ip=1.1.1.1/32\n")||strings.Contains(ipc,"allowed_ip=0.0.0.0/0"){t.Fatal("route narrowing failed")}
 session,e:=NewProtectedSession("probe",1280,8,smokeNoProtect{});if e!=nil{t.Fatal(e)};defer session.Close()
 if e=session.Configure(ipc);e!=nil{t.Fatal("IPC parser rejected probe")}
 if _,e:=PeerProbeConfig(strings.Replace(config,"0.0.0.0/0","10.0.0.0/8",1),s);e==nil{t.Fatal("unauthorized target")}
}

func TestScopedUDP(t *testing.T){
 s,e:=NewProbeScope("exit-a","10.1.2.3","1.1.1.1",443);if e!=nil{t.Fatal(e)}
 p:=make([]byte,28+12+len(probeQuestion));p[0]=0x45;p[9]=17
 binary.BigEndian.PutUint16(p[2:4],uint16(len(p)));binary.BigEndian.PutUint16(p[24:26],uint16(len(p)-20))
 copy(p[12:16],[]byte{10,1,2,3});copy(p[16:20],[]byte{1,1,1,1})
 binary.BigEndian.PutUint16(p[20:22],40002);binary.BigEndian.PutUint16(p[22:24],53)
 p[30]=1;p[33]=1;copy(p[40:],probeQuestion)
 if !s.MatchUDP(p,false,40002)||s.MatchUDP(p,false,40003)||s.MatchUDP(p,true,40002)||s.Match(p,false){t.Fatal("UDP query scope")}
 q:=append([]byte(nil),p...);copy(q[12:16],p[16:20]);copy(q[16:20],p[12:16]);copy(q[20:22],p[22:24]);copy(q[22:24],p[20:22]);q[30]=0x81;q[31]=0x80
 if !s.MatchUDP(q,true,40002)||s.MatchUDP(q,true,0){t.Fatal("UDP reply scope")}
 q[41]='z';if s.MatchUDP(q,true,40002){t.Fatal("foreign question accepted")}
 p[25]--;if s.MatchUDP(p,false,40002){t.Fatal("bad UDP length")}
 home,e:=NewProbeScope("home","10.1.2.3","10.0.0.169",4533);if e!=nil||home.MatchUDP(q,true,40002){t.Fatal("home UDP not authorized")}
}
