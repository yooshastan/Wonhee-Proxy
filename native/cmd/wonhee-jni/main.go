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
	if (n == "home" && route != "198.18.1.0/24")
		|| (n == "internet" && route != "0.0.0.0/0") {
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
	if entry.session == nil { return -3 }
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

func main() {}
