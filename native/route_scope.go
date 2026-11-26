package dualwg

import (
 "encoding/binary"
 "net/netip"
 "strings"
 "time"
)

const routeMaxFlows=4096
type RouteTuple struct {
 Remote netip.Addr
 LocalPort, RemotePort uint16
 Protocol byte
}
type RouteScope struct {
 local netip.Addr
 home netip.Prefix
 isHome bool
 flows map[RouteTuple]time.Time
 nextSweep time.Time
}
func privatePrefix(p netip.Prefix) bool{
 if !p.IsValid()||!p.Addr().Is4()||p!=p.Masked(){return false}
 for _,v:=range []string{"10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"}{
  block:=netip.MustParsePrefix(v)
  if p.Bits()>=block.Bits()&&block.Contains(p.Addr()){return true}
 }
 return false
}
func routePublic(a netip.Addr)bool{
 if !a.Is4()||!a.IsGlobalUnicast()||a.IsPrivate()||a.IsLinkLocalUnicast(){return false}
 for _,p:=range []string{"0.0.0.0/8","100.64.0.0/10","192.0.0.0/24","192.0.2.0/24","198.18.0.0/15","198.51.100.0/24","203.0.113.0/24","240.0.0.0/4"}{
  if netip.MustParsePrefix(p).Contains(a){return false}
 }
 return true
}
// Do not expand the provider's AllowedIPs. Internet exits must explicitly
// cover IPv4 default (or both halves); Home is narrowed to one user CIDR.
func NewRouteScope(role,input,local,home string)(*RouteScope,string,error){
 l,e:=netip.ParseAddr(local);if e!=nil||!l.Is4()||!l.IsGlobalUnicast()||l.IsLinkLocalUnicast(){return nil,"",ErrBadArgument}
 ipc,e:=PeerHandshakeConfig(input);if e!=nil{return nil,"",e}
 s:=&RouteScope{local:l,isHome:role=="home",flows:make(map[RouteTuple]time.Time)}
 if s.isHome{
  s.home,e=netip.ParsePrefix(home);if e!=nil||!privatePrefix(s.home){return nil,"",ErrBadArgument}
 }else if role!="exit-a"&&role!="exit-b"{return nil,"",ErrBadArgument}
 covered,left,right:=false,false,false
 for _,line:=range strings.Split(input,"\n"){
  k,v,ok:=strings.Cut(line,"=");if !ok||strings.TrimSpace(k)!="AllowedIPs"{continue}
  for _,raw:=range strings.Split(v,","){
   p,e:=netip.ParsePrefix(strings.TrimSpace(raw));if e!=nil||!p.Addr().Is4(){continue}
   p=p.Masked()
   if s.isHome {covered=covered||(p.Bits()<=s.home.Bits()&&p.Contains(s.home.Addr()))}else{
    covered=covered||p.Bits()==0
    left=left||p.String()=="0.0.0.0/1";right=right||p.String()=="128.0.0.0/1"
   }
  }
 }
 if !covered&&!(left&&right&&!s.isHome){return nil,"",ErrBadArgument}
 route:="0.0.0.0/0";if s.isHome{route=s.home.String()}
 return s,ipc+"replace_allowed_ips=true\nallowed_ip="+route+"\n",nil
}
func (s *RouteScope) tuple(p []byte,reply bool)(RouteTuple,bool,bool){
 var key RouteTuple
 if len(p)<28||len(p)>1280||p[0]!=0x45||int(binary.BigEndian.Uint16(p[2:4]))!=len(p)||binary.BigEndian.Uint16(p[6:8])&0xbfff!=0{return key,false,false}
 proto:=p[9];syn:=false
 if proto==6{
  if len(p)<40||int(p[32]>>4)*4<20||20+int(p[32]>>4)*4>len(p){return key,false,false}
  syn=p[33]&0x17==2
 }else if proto==17{
  if int(binary.BigEndian.Uint16(p[24:26]))!=len(p)-20{return key,false,false}
 }else{return key,false,false}
 local,remote:=netip.AddrFrom4([4]byte(p[12:16])),netip.AddrFrom4([4]byte(p[16:20]))
 lp,rp:=binary.BigEndian.Uint16(p[20:22]),binary.BigEndian.Uint16(p[22:24])
 if reply{local,remote=remote,local;lp,rp=rp,lp}
 if local!=s.local||lp==0||rp==0||remote==local{return key,false,false}
 if s.isHome {if !s.home.Contains(remote)||!remote.IsGlobalUnicast(){return key,false,false}}else if !routePublic(remote){return key,false,false}
 return RouteTuple{remote,lp,rp,proto},syn,true
}
func (s *RouteScope) sweep(now time.Time){
 if now.Before(s.nextSweep){return}
 for k,expires:=range s.flows{if !now.Before(expires){delete(s.flows,k)}}
 s.nextSweep=now.Add(time.Second)
}
// Called under owning session mutex. No unsolicited replies, no midstream TCP
// admission, no flow reuse across sessions through this ledger.
func (s *RouteScope) Outgoing(p []byte)bool{return s.outgoing(p,time.Now())}
func (s *RouteScope) outgoing(p []byte,now time.Time)bool{
 key,syn,ok:=s.tuple(p,false);if !ok{return false}
 s.sweep(now)
 expires,exists:=s.flows[key]
 if !exists||!now.Before(expires){
  if key.Protocol==6&&!syn{return false}
  if !exists&&len(s.flows)>=routeMaxFlows{return false}
 }
 ttl:=60*time.Second;if key.Protocol==6{ttl=5*time.Minute}
 s.flows[key]=now.Add(ttl);return true
}
func (s *RouteScope) Incoming(p []byte)bool{return s.incoming(p,time.Now())}
func (s *RouteScope) incoming(p []byte,now time.Time)bool{
 key,_,ok:=s.tuple(p,true);if !ok{return false}
 expiry,ok:=s.flows[key];return ok&&now.Before(expiry)
}
