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

//export WNCreateTestSession
func WNCreateTestSession(name *C.char) C.int64_t {
	// Negative results are fixed redacted stage codes; positive results alone
	// are session handles. Never return IPC input or upstream error strings.
	if name == nil || C.wn_has_service() != 1 { return -1 }
	session, err := dualwg.NewProtectedSession(C.GoString(name), 1280, 32, androidProtector{})
	if err != nil { return -2 }
	config, err := dualwg.NewEphemeralSmokeConfig()
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
	if handle == 0 || handle > (1<<63)-1 { session.Close(); return -6 }
	sessionsMu.Lock()
	sessions[handle] = &sessionEntry{session: session}
	sessionsMu.Unlock()
	return C.int64_t(handle)
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

// Keep unsafe linked in this bridge package only for future packet-array JNI
// operations; no Java-provided memory is retained by the current smoke test.
var _ = unsafe.Pointer(nil)
