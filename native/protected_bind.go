package dualwg

import (
	"errors"
	"net"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

// SocketProtector is the narrow platform callback. On Android the real
// owning VpnService must call protect(fd) and return its actual result.
// The callback must not re-enter the Bind or close the supplied descriptor.
type SocketProtector interface {
	Protect(fd int) bool
}

var errProtection = errors.New("protected WireGuard UDP bind unavailable")
var errExternalMark = errors.New("external WireGuard mark not allowed in protected bind")

// protectedBind wraps the pinned WireGuard standard bind. Both IPv4/IPv6
// sockets must be present and successfully protected before any receive
// function or send is exposed to the WireGuard device. A missing family
// currently fails closed rather than guessing which descriptor is usable.
type protectedBind struct {
	mu sync.RWMutex
	inner conn.Bind
	protector SocketProtector
	ready bool
}

func newProtectedBind(inner conn.Bind, protector SocketProtector) *protectedBind {
	return &protectedBind{inner: inner, protector: protector}
}

var _ conn.Bind = (*protectedBind)(nil)

func (b *protectedBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ready {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	if b.inner == nil || b.protector == nil {
		return nil, 0, errProtection
	}
	peek, ok := b.inner.(conn.PeekLookAtSocketFd)
	if !ok {
		return nil, 0, errProtection
	}
	fns, actual, err := b.inner.Open(port)
	if err != nil {
		_ = b.inner.Close()
		return nil, 0, errProtection
	}
	success := false
	defer func() {
		if !success {
			_ = b.inner.Close()
		}
	}()
	// The pinned StdNetBind has exactly one receive function per active
	// address family, and its Android peek methods require both sockets.
	if len(fns) != 2 || actual == 0 || fns[0] == nil || fns[1] == nil {
		return nil, 0, errProtection
	}
	v4, e4 := peek.PeekLookAtSocketFd4()
	v6, e6 := peek.PeekLookAtSocketFd6()
	if e4 != nil || e6 != nil || v4 < 0 || v6 < 0 || v4 == v6 {
		return nil, 0, errProtection
	}
	if !b.protector.Protect(v4) || !b.protector.Protect(v6) {
		return nil, 0, errProtection
	}
	b.ready = true
	success = true
	return fns, actual, nil
}

func (b *protectedBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ready = false
	if b.inner == nil { return nil }
	return b.inner.Close()
}

func (b *protectedBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if !b.ready { return net.ErrClosed }
	return b.inner.Send(bufs, ep)
}

// Android owns its socket protection mark. Never clear it or replace it
// with an arbitrary profile fwmark through this adapter.
func (b *protectedBind) SetMark(mark uint32) error {
	if mark != 0 { return errExternalMark }
	return nil
}

func (b *protectedBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	if b.inner == nil { return nil, errProtection }
	return b.inner.ParseEndpoint(s)
}

func (b *protectedBind) BatchSize() int {
	if b.inner == nil { return 1 }
	return b.inner.BatchSize()
}
