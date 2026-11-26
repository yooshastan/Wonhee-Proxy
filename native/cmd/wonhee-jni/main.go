//go:build android && cgo

package main

/*
#include "jni_bridge.h"
*/
import "C"

import (
	"sync"
	"sync/atomic"
	"unsafe"

	dualwg "github.com/yooshastan/Wonhee-Proxy/native"
)

type sessionEntry struct {
	mu sync.Mutex
	session *dualwg.Session
	handshakeOnly bool
	probe *dualwg.ProbeScope
	probePorts [4]uint16
	udpPort uint16
}

type androidProtector struct{}
func (androidProtector) Protect(fd int) bool {
	return C.wn_protect_socket(C.int(fd)) == 1
}

var (
	sessionsMu sync.RWMutex
	sessions = make(map[uint64]*sessionEntry)
	nextHandle atomic.Uint64
)

func createProtectedSession(name, allowedIP string) C.int64_t {
	if C.wn_has_service() != 1 { return -1 }
	session, err := dualwg.NewProtectedSession(name, 1280, 32, androidProtector{})
	if err != nil { return -2 }
	config, err := dualwg.NewEphemeralSmokeConfigForAllowedIP(allowedIP)
	if err != nil { session.Close(); return -3 }
	if err = session.Configure(config); err != nil {
		session.Close()
		return -4
	}
	if err = session.Start(); err != nil {
		session.Close()
		return -5
	}
	handle := nextHandle.Add(1)
	if handle == 0 || handle > (1<<63)-1 {
		session.Close()
		return -6
	}
	sessionsMu.Lock()
	sessions[handle] = &sessionEntry{session: session}
	sessionsMu.Unlock()
	return C.int64_t(handle)
}

//export WNCreateTestSession
func WNCreateTestSession(name *C.char) C.int64_t {
	if name == nil { return -1 }
	return createProtectedSession(C.GoString(name), "192.0.2.0/24")
}

//export WNCreatePacketTestSession
func WNCreatePacketTestSession(name *C.char, allowedIP *C.char) C.int64_t {
	if name == nil || allowedIP == nil { return -7 }
	n := C.GoString(name)
	route := C.GoString(allowedIP)
	if (n == "home" && route != "198.18.1.0/24") ||
		(n == "internet" && route != "0.0.0.0/0") {
		return -7
	}
	return createProtectedSession(n, route)
}

func lookupSession(handle uint64) *sessionEntry {
	if handle == 0 { return nil }
	sessionsMu.RLock()
	entry := sessions[handle]
	sessionsMu.RUnlock()
	return entry
}

//export WNInjectPacket
func WNInjectPacket(handle C.uint64_t, data *C.char, length C.int) C.int {
	if data == nil || length < 20 || length > 1280 { return -1 }
	entry := lookupSession(uint64(handle))
	if entry == nil { return -2 }
	packet := C.GoBytes(unsafe.Pointer(data), length)
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.session == nil || entry.handshakeOnly { return -3 }
	if entry.probe != nil && !(entry.probe.OwnedTCP(packet,false,entry.probePorts)) && !entry.probe.MatchUDP(packet,false,entry.udpPort) { return -5 }
	if err := entry.session.Tun.Inject(packet); err != nil { return -4 }
	return 1
}

//export WNPacketStats
func WNPacketStats(handle C.uint64_t, injected *C.int64_t,
	read *C.int64_t, dropped *C.int64_t) C.int {
	if injected == nil || read == nil || dropped == nil { return 0 }
	entry := lookupSession(uint64(handle))
	if entry == nil { return 0 }
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.session == nil { return 0 }
	stats := entry.session.Tun.Stats()
	*injected = C.int64_t(stats.Injected)
	*read = C.int64_t(stats.Read)
	*dropped = C.int64_t(stats.Dropped)
	return 1
}

//export WNCloseSession
func WNCloseSession(handle C.uint64_t) C.int {
	id := uint64(handle)
	if id == 0 { return 0 }
	sessionsMu.Lock()
	entry := sessions[id]
	delete(sessions, id)
	sessionsMu.Unlock()
	if entry == nil { return 0 }
	entry.mu.Lock()
	entry.session.Close()
	entry.session = nil
	entry.mu.Unlock()
	return 1
}

//export WNValidatePeerProfile
func WNValidatePeerProfile(config *C.char) C.int {
 if config==nil {return C.int(dualwg.PeerProfileFormat)}
 return C.int(dualwg.PeerProfileStatus(C.GoString(config)))
}

//export WNCreatePeerSession
func WNCreatePeerSession(name,config *C.char) C.int64_t {
 if name==nil || config==nil || C.wn_has_service()!=1 {return -1}
 n:=C.GoString(name)
 if n!="exit-a" && n!="exit-b" && n!="home" {return -7}
 ipc,e:=dualwg.PeerHandshakeConfig(C.GoString(config));if e!=nil {return -3}
 session,e:=dualwg.NewProtectedSession(n,1280,8,androidProtector{});if e!=nil {return -2}
 if e=session.Configure(ipc);e!=nil {session.Close();return -4}
 if e=session.Start();e!=nil {session.Close();return -5}
 handle:=nextHandle.Add(1)
 if handle==0 || handle>(1<<63)-1 {session.Close();return -6}
 sessionsMu.Lock()
 sessions[handle]=&sessionEntry{session:session,handshakeOnly:true}
 sessionsMu.Unlock()
 return C.int64_t(handle)
}

//export WNPeerStats
func WNPeerStats(handle C.uint64_t, hs,rx,tx *C.int64_t) C.int {
 if hs==nil || rx==nil || tx==nil {return 0}
 entry:=lookupSession(uint64(handle));if entry==nil {return 0}
 entry.mu.Lock();defer entry.mu.Unlock()
 if entry.session==nil || (!entry.handshakeOnly && entry.probe==nil) {return 0}
 h,r,t,e:=entry.session.PeerSnapshot();if e!=nil {return 0}
 *hs=C.int64_t(h);*rx=C.int64_t(r);*tx=C.int64_t(t)
 return 1
}

//export WNCreateProbeSession
func WNCreateProbeSession(name,config,local,target,stream *C.char,port C.int) C.int64_t {
 if name==nil||config==nil||local==nil||target==nil||stream==nil||C.wn_has_service()!=1 {return -1}
 n:=C.GoString(name)
 scope,e:=dualwg.NewProbeScope(n,C.GoString(local),C.GoString(target),int(port));if e!=nil{return -7}
 if e=scope.SetStream(C.GoString(stream));e!=nil{return -7}
 ipc,e:=dualwg.PeerProbeConfig(C.GoString(config),scope);if e!=nil{return -3}
 session,e:=dualwg.NewProtectedSession(n,1280,512,androidProtector{});if e!=nil{return -2}
 if e=session.Configure(ipc);e!=nil{session.Close();return -4}
 if e=session.Start();e!=nil{session.Close();return -5}
 handle:=nextHandle.Add(1);if handle==0||handle>(1<<63)-1{session.Close();return -6}
 sessionsMu.Lock();sessions[handle]=&sessionEntry{session:session,probe:scope};sessionsMu.Unlock()
 return C.int64_t(handle)
}

//export WNPollProbePacket
func WNPollProbePacket(handle C.uint64_t,data *C.char,capacity C.int) C.int {
 if data==nil||capacity<1280{return -1}
 entry:=lookupSession(uint64(handle));if entry==nil{return -2}
 entry.mu.Lock();defer entry.mu.Unlock()
 if entry.session==nil||entry.probe==nil{return -3}
 packet,ok:=entry.session.Tun.Poll();if !ok{return 0}
 if !(entry.probe.OwnedTCP(packet,true,entry.probePorts))&&!entry.probe.MatchUDP(packet,true,entry.udpPort){return -4}
 copy(unsafe.Slice((*byte)(unsafe.Pointer(data)),int(capacity)),packet)
 return C.int(len(packet))
}
//export WNRegisterProbePorts
func WNRegisterProbePorts(handle C.uint64_t,a,b,c,d,udp C.int) C.int {
 if udp<0||udp>65535{return 0}
 values:=[4]C.int{a,b,c,d}
 for i,v:=range values{if v<1||v>65535{return 0};for k:=0;k<i;k++{if values[k]==v{return 0}}}
 entry:=lookupSession(uint64(handle));if entry==nil{return 0}
 entry.mu.Lock();defer entry.mu.Unlock()
 if entry.session==nil||entry.probe==nil||entry.probePorts!=[4]uint16{}{return 0}
 isExit:=entry.probe.Target.String()=="1.1.1.1"||entry.probe.Target.String()=="1.0.0.1"
 if (isExit&&udp==0)||(!isExit&&udp!=0){return 0}
 entry.udpPort=uint16(udp)
 entry.probePorts=[4]uint16{uint16(a),uint16(b),uint16(c),uint16(d)}
 return 1
}
func main() {}
