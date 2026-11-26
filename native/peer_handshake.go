package dualwg

import (
 "crypto/ecdh"
 "encoding/base64"
 "encoding/hex"
 "net"
 "net/netip"
 "strconv"
 "strings"
)

// Fixed redacted status codes cross JNI; never return config values or parse errors.
type PeerProfileError int
const (
 PeerProfileOK PeerProfileError = 1
 PeerProfileFormat PeerProfileError = 2
 PeerProfilePrivateKey PeerProfileError = 3
 PeerProfilePublicKey PeerProfileError = 4
 PeerProfileIdentity PeerProfileError = 5
 PeerProfileAllowedIPs PeerProfileError = 6
 PeerProfilePortOrKeepalive PeerProfileError = 7
 PeerProfilePresharedKey PeerProfileError = 8
 PeerProfileHostname PeerProfileError = 9
 PeerProfileEndpoint PeerProfileError = 10
)
func (e PeerProfileError) Error() string {return "peer profile rejected"}
func PeerProfileStatus(input string) PeerProfileError {
 _,err:=PeerHandshakeConfig(input)
 if err==nil {return PeerProfileOK}
 if code,ok:=err.(PeerProfileError);ok {return code}
 return PeerProfileFormat
}

// Accept valid DNS names for storage, never resolve here or emit them into IPC.
func validPeerHostname(s string) bool {
 s=strings.TrimSuffix(s,".")
 if len(s)==0 || len(s)>253 {return false}
 hasLetter:=false
 for _,label:=range strings.Split(s,".") {
  if len(label)==0 || len(label)>63 || label[0]=='-' || label[len(label)-1]=='-' {return false}
  for _,c:=range label {
   if c>='a'&&c<='z'||c>='A'&&c<='Z' {hasLetter=true;continue}
   if c>='0'&&c<='9'||c=='-' {continue}
   return false
  }
 }
 return hasLetter
}

// PeerHandshakeConfig emits only numeric endpoint, key material, ephemeral
// listen port and keepalive. No allowed_ip, payload, OS routing or DNS lookup.
func PeerHandshakeConfig(input string) (string,error) {
 if len(input)==0 || len(input)>32768 {return "",PeerProfileFormat}
 section:=0
 fields:=map[string]string{}
 for _,raw:=range strings.Split(input,"\n") {
  line:=strings.TrimSpace(raw)
  if line=="" {continue}
  if line=="[Interface]" && section==0 {section=1;continue}
  if line=="[Peer]" && section==1 {section=2;continue}
  key,value,ok:=strings.Cut(line,"=")
  key=strings.TrimSpace(key);value=strings.TrimSpace(value)
  if !ok || value=="" || strings.ContainsAny(value,"\x00\r\n") {return "",PeerProfileFormat}
  switch {
  case section==1 && (key=="PrivateKey" || key=="ListenPort"):
  case section==2 && (key=="PublicKey" || key=="PresharedKey" || key=="AllowedIPs" || key=="Endpoint" || key=="PersistentKeepalive"):
  default:return "",PeerProfileFormat
  }
  if _,exists:=fields[key];exists {return "",PeerProfileFormat}
  fields[key]=value
 }
 if section!=2 {return "",PeerProfileFormat}
 decode:=func(s string)([]byte,bool){
  b,e:=base64.StdEncoding.Strict().DecodeString(s)
  return b,e==nil && len(b)==32 && base64.StdEncoding.EncodeToString(b)==s
 }
 private,ok:=decode(fields["PrivateKey"]);if !ok {return "",PeerProfilePrivateKey}
 public,ok:=decode(fields["PublicKey"]);if !ok {return "",PeerProfilePublicKey}
 zero:=make([]byte,32)
 if string(private)==string(zero) {return "",PeerProfilePrivateKey}
 if string(public)==string(zero) {return "",PeerProfilePublicKey}
 own,e:=ecdh.X25519().NewPrivateKey(private);if e!=nil || string(own.PublicKey().Bytes())==string(public) {return "",PeerProfileIdentity}
 for _,p:=range strings.Split(fields["AllowedIPs"],",") {
  if _,e:=netip.ParsePrefix(strings.TrimSpace(p));e!=nil {return "",PeerProfileAllowedIPs}
 }
 for _,k:=range []string{"ListenPort","PersistentKeepalive"} {
  if s,ok:=fields[k];ok {if _,e:=strconv.ParseUint(s,10,16);e!=nil {return "",PeerProfilePortOrKeepalive}}
 }
 var psk []byte
 if v,ok:=fields["PresharedKey"];ok {
  var valid bool
  psk,valid=decode(v);if !valid {return "",PeerProfilePresharedKey}
 }
 endpoint,e:=netip.ParseAddrPort(fields["Endpoint"])
 if e!=nil {
  host,port,splitErr:=net.SplitHostPort(fields["Endpoint"])
  p,portErr:=strconv.ParseUint(port,10,16)
  if splitErr==nil && portErr==nil && p>0 && validPeerHostname(host) && !strings.HasPrefix(fields["Endpoint"],"[") {
   return "",PeerProfileHostname
  }
  return "",PeerProfileEndpoint
 }
 ip:=endpoint.Addr().Unmap()
 if endpoint.Port()==0 || ip.Zone()!="" || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() {return "",PeerProfileEndpoint}
 endpoint=netip.AddrPortFrom(ip,endpoint.Port())
 var out strings.Builder
 out.WriteString("private_key="+hex.EncodeToString(private)+"\nlisten_port=0\nreplace_peers=true\npublic_key="+hex.EncodeToString(public)+"\n")
 if psk!=nil {out.WriteString("preshared_key="+hex.EncodeToString(psk)+"\n")}
 out.WriteString("endpoint="+endpoint.String()+"\npersistent_keepalive_interval=5\n")
 return out.String(),nil
}
