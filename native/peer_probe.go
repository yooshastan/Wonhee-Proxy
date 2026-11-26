package dualwg

import (
 "encoding/binary"
 "bytes"
 "net/netip"
 "strings"
)

// ProbeScope permits bounded-size IPv4 TCP segments for one numeric IPv4 destination.
// The Android side additionally owns the ephemeral source port and TUN address.
type ProbeScope struct {
 Local, Target netip.Addr
 Port uint16
 Stream netip.Addr
}
func NewProbeScope(role,local,target string,port int) (*ProbeScope,error) {
 l,e:=netip.ParseAddr(local);if e!=nil || !l.Is4() || !l.IsGlobalUnicast() || l.IsLinkLocalUnicast() {return nil,ErrBadArgument}
 t,e:=netip.ParseAddr(target);if e!=nil || !t.Is4() || !t.IsGlobalUnicast() || t.IsLinkLocalUnicast() || t==l || port<1 || port>65535 {return nil,ErrBadArgument}
 switch role {
 case "exit-a":if target!="1.1.1.1" || port!=443 {return nil,ErrBadArgument}
 case "exit-b":if target!="1.0.0.1" || port!=443 {return nil,ErrBadArgument}
 case "home":if !t.IsPrivate() {return nil,ErrBadArgument}
 default:return nil,ErrBadArgument
 }
 return &ProbeScope{Local:l,Target:t,Port:uint16(port)},nil
}
// Separate exact /32 for the certificate-verified transfer test. The Java
// caller resolves the fixed service name using authenticated bootstrap DNS.
func (s *ProbeScope) SetStream(target string) error {
 if s==nil{return ErrBadArgument}
 if s.Target.String()!="1.1.1.1"&&s.Target.String()!="1.0.0.1"{
  if target!=""{return ErrBadArgument};return nil
 }
 t,e:=netip.ParseAddr(target)
 if e!=nil||!t.Is4()||!t.IsGlobalUnicast()||t.IsPrivate()||t.IsLinkLocalUnicast()||t.IsLoopback()||t==s.Local||t==s.Target||target=="1.1.1.1"||target=="1.0.0.1"{return ErrBadArgument}
 s.Stream=t;return nil
}
func (s *ProbeScope) MatchStream(p []byte,reply bool) bool {
 if s==nil||!s.Stream.IsValid(){return false}
 stream:=ProbeScope{Local:s.Local,Target:s.Stream,Port:443}
 return stream.Match(p,reply)
}
// Only the first pair owns the short-probe target. The second pair owns
// the streaming target (or the same private Home target for the Home role).
func (s *ProbeScope) OwnedTCP(p []byte,reply bool,ports [4]uint16) bool {
 if s==nil{return false}
 first:=s.Match(p,reply)&&ProbePort(p,reply,[2]uint16{ports[0],ports[1]})
 second:=ProbePort(p,reply,[2]uint16{ports[2],ports[3]})
 if s.Stream.IsValid(){return first||(second&&s.MatchStream(p,reply))}
 return first||(second&&s.Match(p,reply))
}
func (s *ProbeScope) Match(p []byte,reply bool) bool {
 if s==nil || len(p)<40 || len(p)>1280 || p[0]!=0x45 || p[9]!=6 || int(binary.BigEndian.Uint16(p[2:4]))!=len(p) || binary.BigEndian.Uint16(p[6:8])&0xbfff!=0 {return false}
 header:=int(p[32]>>4)*4
 if header<20 || 20+header>len(p) {return false}
 src:=netip.AddrFrom4([4]byte(p[12:16]));dst:=netip.AddrFrom4([4]byte(p[16:20]))
 sp:=binary.BigEndian.Uint16(p[20:22]);dp:=binary.BigEndian.Uint16(p[22:24])
 if sp==0||dp==0 {return false}
 if reply {return src==s.Target&&dst==s.Local&&sp==s.Port}
 return src==s.Local&&dst==s.Target&&dp==s.Port
}
// Forwarding uses only a /32 that was already authorized by the imported peer.
// All other AllowedIPs remain absent from this native diagnostic session.
func PeerProbeConfig(input string,scope *ProbeScope)(string,error) {
 if scope==nil{return "",ErrBadArgument}
 ipc,e:=PeerHandshakeConfig(input);if e!=nil{return "",e}
 covered:=false
 streamCovered:=!scope.Stream.IsValid()
 for _,line:=range strings.Split(input,"\n") {
  k,v,ok:=strings.Cut(line,"=")
  if !ok||strings.TrimSpace(k)!="AllowedIPs"{continue}
  for _,p:=range strings.Split(v,",") {
   prefix,e:=netip.ParsePrefix(strings.TrimSpace(p))
   if e==nil&&prefix.Contains(scope.Target){covered=true}
   if e==nil&&scope.Stream.IsValid()&&prefix.Contains(scope.Stream){streamCovered=true}
  }
 }
 if !covered||!streamCovered{return "",ErrBadArgument}
 result:=ipc+"replace_allowed_ips=true\nallowed_ip="+scope.Target.String()+"/32\n"
 if scope.Stream.IsValid(){result+="allowed_ip="+scope.Stream.String()+"/32\n"}
 return result,nil
}

// ProbePort matches one of the explicitly registered local TCP ports.
// Called under the owning JNI session lock; never infer flow from remote IP alone.
func ProbePort(p []byte,reply bool,ports [2]uint16) bool {
 if len(p)<40 || p[0]!=0x45 || p[9]!=6{return false}
 offset:=20;if reply{offset=22}
 port:=binary.BigEndian.Uint16(p[offset:offset+2])
 return port!=0&&(port==ports[0]||port==ports[1])
}

// DNS test traffic is limited to the fixed example.com A question on the
// existing public probe host. No general UDP or resolver access is enabled.
var probeQuestion=[]byte{7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1}
func (s *ProbeScope) MatchUDP(p []byte,reply bool,localPort uint16) bool {
 if s==nil || localPort==0 || s.Port!=443 || (s.Target.String()!="1.1.1.1"&&s.Target.String()!="1.0.0.1") {return false}
 if len(p)<28+12+len(probeQuestion)||len(p)>1280||p[0]!=0x45||p[9]!=17||int(binary.BigEndian.Uint16(p[2:4]))!=len(p)||binary.BigEndian.Uint16(p[6:8])&0xbfff!=0||int(binary.BigEndian.Uint16(p[24:26]))!=len(p)-20{return false}
 src:=netip.AddrFrom4([4]byte(p[12:16]));dst:=netip.AddrFrom4([4]byte(p[16:20]))
 sp:=binary.BigEndian.Uint16(p[20:22]);dp:=binary.BigEndian.Uint16(p[22:24])
 dns:=p[28:]
 if binary.BigEndian.Uint16(dns[4:6])!=1||!bytes.Equal(dns[12:12+len(probeQuestion)],probeQuestion){return false}
 if reply {return src==s.Target&&dst==s.Local&&sp==53&&dp==localPort&&dns[2]&0xf8==0x80}
 return src==s.Local&&dst==s.Target&&sp==localPort&&dp==53&&len(dns)==12+len(probeQuestion)&&dns[2]==1&&dns[3]==0&&bytes.Equal(dns[6:12],[]byte{0,0,0,0,0,0})
}
