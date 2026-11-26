//go:build android && cgo

package main

/*
#include "jni_bridge.h"
*/
import "C"

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
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

func makeEphemeralSmokeConfig() (string, error) {
	curve := ecdh.X25519()
	private, err := curve.GenerateKey(rand.Reader)
	if err != nil { return "", err }
	peer, err := curve.GenerateKey(rand.Reader)
	if err != nil { return "", err }
	return fmt.Sprintf(
		"private_key=%s\nreplace_peers=true\npublic_key=%s\nallowed_ip=192.0.2.0/24\n",
		base64.StdEncoding.EncodeToString(private.Bytes()),
		base64.StdEncoding.EncodeToString(peer.PublicKey().Bytes())), nil
}

//export WNCreateTestSession
func WNCreateTestSession(name *C.char) C.uint64_t {
	if name == nil || C.wn_has_service() != 1 { return 0 }
	session, err := dualwg.NewProtectedSession(C.GoString(name), 1280, 32, androidProtector{})
	if err != nil { return 0 }
	config, err := makeEphemeralSmokeConfig()
	if err != nil { session.Close(); return 0 }
	if err = session.Configure(config); err != nil {
		session.Close()
		return 0
	}
	if err = session.Start(); err != nil {
		session.Close()
		return 0
	}
	handle := nextHandle.Add(1)
	if handle == 0 { session.Close(); return 0 }
	sessionsMu.Lock()
	sessions[handle] = &sessionEntry{session: session}
	sessionsMu.Unlock()
	return C.uint64_t(handle)
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
