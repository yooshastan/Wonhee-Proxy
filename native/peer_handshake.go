package dualwg

import (
 "crypto/ecdh"
 "encoding/base64"
 "encoding/hex"
 "net/netip"
 "strconv"
 "strings"
)

// PeerHandshakeConfig converts a single canonical wg setconf profile into
// an isolated handshake-only IPC config. Never emit routes or payload policy.
// Numeric endpoints avoid implicit resolver traffic; ephemeral listen ports
// avoid collisions; a five-second keepalive initiates authenticated handshakes.
func PeerHandshakeConfig(input string) (string,error) {
 if len(input)==0 || len(input)>32768 {return "",ErrBadArgument}
 section:=0
 fields:=map[string]string{}
 for _,raw:=range strings.Split(input,"\n") {
  line:=strings.TrimSpace(raw)
  if line=="" {continue}
  if line=="[Interface]" && section==0 {section=1;continue}
  if line=="[Peer]" && section==1 {section=2;continue}
  key,value,ok:=strings.Cut(line,"=")
  key=strings.TrimSpace(key);value=strings.TrimSpace(value)
  if !ok || value=="" || strings.ContainsAny(value,"\x00\r\n") {return "",ErrBadArgument}
  switch {
  case section==1 && (key=="PrivateKey" || key=="ListenPort"):
  case section==2 && (key=="PublicKey" || key=="PresharedKey" || key=="AllowedIPs" || key=="Endpoint" || key=="PersistentKeepalive"):
  default:return "",ErrBadArgument
  }
  if _,exists:=fields[key];exists {return "",ErrBadArgument}
  fields[key]=value
 }
 if section!=2 {return "",ErrBadArgument}
 decode:=func(s string)([]byte,error){
  b,e:=base64.StdEncoding.Strict().DecodeString(s)
  if e!=nil || len(b)!=32 || base64.StdEncoding.EncodeToString(b)!=s {return nil,ErrBadArgument}
  return b,nil
 }
 private,e:=decode(fields["PrivateKey"]);if e!=nil {return "",e}
 public,e:=decode(fields["PublicKey"]);if e!=nil {return "",e}
 zero:=make([]byte,32)
 if string(private)==string(zero) || string(public)==string(zero) {return "",ErrBadArgument}
 own,e:=ecdh.X25519().NewPrivateKey(private);if e!=nil || string(own.PublicKey().Bytes())==string(public) {return "",ErrBadArgument}
 endpoint,e:=netip.ParseAddrPort(fields["Endpoint"])
 if e!=nil || endpoint.Port()==0 || endpoint.Addr().Zone()!="" || endpoint.Addr().IsUnspecified() || endpoint.Addr().IsMulticast() || endpoint.Addr().IsLoopback() {return "",ErrBadArgument}
 for _,p:=range strings.Split(fields["AllowedIPs"],",") {
  if _,e:=netip.ParsePrefix(strings.TrimSpace(p));e!=nil {return "",ErrBadArgument}
 }
 for _,k:=range []string{"ListenPort","PersistentKeepalive"} {
  if s,ok:=fields[k];ok {if _,e:=strconv.ParseUint(s,10,16);e!=nil {return "",ErrBadArgument}}
 }
 var out strings.Builder
 out.WriteString("private_key="+hex.EncodeToString(private)+"\nlisten_port=0\nreplace_peers=true\npublic_key="+hex.EncodeToString(public)+"\n")
 if v,ok:=fields["PresharedKey"];ok {
  p,e:=decode(v);if e!=nil {return "",e}
  out.WriteString("preshared_key="+hex.EncodeToString(p)+"\n")
 }
 // Intentionally omit every allowed_ip: remote payload is not authorized.
 out.WriteString("endpoint="+endpoint.String()+"\npersistent_keepalive_interval=5\n")
 return out.String(),nil
}
