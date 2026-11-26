package dualwg

import (
 "crypto/ecdh"
 "crypto/rand"
 "encoding/base64"
 "strings"
 "testing"
)
func TestPeerHandshakeConfig(t *testing.T) {
 key:=func() *ecdh.PrivateKey {k,e:=ecdh.X25519().GenerateKey(rand.Reader);if e!=nil {t.Fatal("key generation")};return k}
 a,b:=key(),key()
 enc:=base64.StdEncoding.EncodeToString
 input:="[Interface]\nPrivateKey = "+enc(a.Bytes())+"\nListenPort = 51820\n[Peer]\nPublicKey = "+enc(b.PublicKey().Bytes())+"\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = [2001:db8::1]:51820\nPersistentKeepalive = 25\n"
 ipc,e:=PeerHandshakeConfig(input)
 if e!=nil || strings.Contains(ipc,"allowed_ip=") || !strings.Contains(ipc,"listen_port=0\n") || !strings.Contains(ipc,"persistent_keepalive_interval=5\n") {t.Fatal("invalid diagnostic IPC")}
 s,e:=NewProtectedSession("peer",1280,4,smokeNoProtect{});if e!=nil {t.Fatal("construction")}
 defer s.Close()
 if e=s.Configure(ipc);e!=nil {t.Fatal("actual IPC parser rejected profile")}
 for _,bad:=range []string{
 strings.Replace(input,"[2001:db8::1]:51820","example.com:51820",1),
 strings.Replace(input,"[2001:db8::1]:51820","[::]:51820",1),
 input+"Endpoint = 192.0.2.1:51820\n",
 input+"[Peer]\n",
 input+"fwmark = 1\n",
 strings.Replace(input,enc(a.Bytes()),"bad",1),
 } {if _,e:=PeerHandshakeConfig(bad);e==nil {t.Fatal("unsafe config accepted")}}
}
