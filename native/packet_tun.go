package dualwg

import (
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/tun"
)

var (
	ErrClosed      = errors.New("packet device closed")
	ErrQueueFull   = errors.New("packet queue full")
	ErrPacketSize  = errors.New("invalid packet size")
	ErrBadArgument = errors.New("invalid packet buffer")
)

type PacketStats struct {
	Injected uint64
	Read     uint64
	Written  uint64
	Polled   uint64
	Dropped  uint64
}

// PacketTun is a bounded, user-space implementation of tun.Device. One
// instance belongs to exactly one encrypted WireGuard device. No OS network
// interface or UDP socket is created here. Packet ownership is explicit.
type PacketTun struct {
	name      string
	mtu       int
	incoming  chan []byte
	outgoing  chan []byte
	events    chan tun.Event
	closed    chan struct{}
	closeOnce sync.Once

	injected atomic.Uint64
	read     atomic.Uint64
	written  atomic.Uint64
	polled   atomic.Uint64
	dropped  atomic.Uint64
}

// NewPacketTun creates a bounded interface. Its mtu must leave room for the
// IP packet; the caller must independently constrain the Android VPN MTU.
func NewPacketTun(name string, mtu, queueDepth int) (*PacketTun, error) {
	if name == "" || len(name) > 15 || mtu < 576 || mtu > 65535 || queueDepth < 1 || queueDepth > 4096 {
		return nil, ErrBadArgument
	}
	return &PacketTun{
		name: name, mtu: mtu,
		incoming: make(chan []byte, queueDepth),
		outgoing: make(chan []byte, queueDepth),
		events: make(chan tun.Event, 1),
		closed: make(chan struct{}),
	}, nil
}

func (t *PacketTun) File() *os.File { return nil }
func (t *PacketTun) MTU() (int, error) { return t.mtu, nil }
func (t *PacketTun) Name() (string, error) { return t.name, nil }
func (t *PacketTun) Events() <-chan tun.Event { return t.events }
func (t *PacketTun) BatchSize() int { return 1 }

func (t *PacketTun) Close() error {
	t.closeOnce.Do(func() {
		close(t.closed)
		close(t.events)
	})
	return nil
}

// Stats is an atomic snapshot. It is diagnostic only and contains no packet data.
func (t *PacketTun) Stats() PacketStats {
	return PacketStats{
		Injected: t.injected.Load(),
		Read:     t.read.Load(),
		Written:  t.written.Load(),
		Polled:   t.polled.Load(),
		Dropped:  t.dropped.Load(),
	}
}

// Read returns a packet to wireguard-go. Offsets and lengths are kept in the
// shape required by tun.Device. It fails closed when the interface is stopped.
func (t *PacketTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) < 1 || len(sizes) < 1 || offset < 0 || offset > len(bufs[0]) {
		return 0, ErrBadArgument
	}
	select {
	case <-t.closed:
		return 0, io.EOF
	default:
	}
	select {
	case <-t.closed:
		return 0, io.EOF
	case p := <-t.incoming:
		if len(p)+offset > len(bufs[0]) {
			t.dropped.Add(1)
			return 0, ErrPacketSize
		}
		copy(bufs[0][offset:], p)
		sizes[0] = len(p)
		t.read.Add(1)
		return 1, nil
	}
}

// Write receives a decrypted packet from wireguard-go. Reject congestion
// rather than blocking the crypto worker or rerouting to another session.
func (t *PacketTun) Write(bufs [][]byte, offset int) (int, error) {
	if offset < 0 {
		return 0, ErrBadArgument
	}
	select {
	case <-t.closed:
		return 0, ErrClosed
	default:
	}
	for i, p := range bufs {
		if offset > len(p) || len(p)-offset == 0 || len(p)-offset > t.mtu {
			return i, ErrPacketSize
		}
		copyOf := append([]byte(nil), p[offset:]...)
		select {
		case <-t.closed:
			t.dropped.Add(1)
			return i, ErrClosed
		case t.outgoing <- copyOf:
			t.written.Add(1)
		default:
			t.dropped.Add(1)
			return i, ErrQueueFull
		}
	}
	return len(bufs), nil
}

// Inject moves one validated, policy-selected Android packet into exactly one
// session's WireGuard crypto queue. Production callers must additionally apply
// their validated per-session address translation before using this method.
func (t *PacketTun) Inject(packet []byte) error {
	if len(packet) == 0 || len(packet) > t.mtu {
		return ErrPacketSize
	}
	copyOf := append([]byte(nil), packet...)
	select {
	case <-t.closed:
		t.dropped.Add(1)
		return ErrClosed
	default:
	}
	select {
	case <-t.closed:
		t.dropped.Add(1)
		return ErrClosed
	case t.incoming <- copyOf:
		t.injected.Add(1)
		return nil
	default:
		t.dropped.Add(1)
		return ErrQueueFull
	}
}

// Poll takes one decrypted packet off a session queue. Production callers must
// validate reply ownership before writing the packet to Android's single TUN.
func (t *PacketTun) Poll() ([]byte, bool) {
	select {
	case <-t.closed:
		return nil, false
	default:
	}
	select {
	case <-t.closed:
		return nil, false
	case packet := <-t.outgoing:
		t.polled.Add(1)
		return packet, true
	default:
		return nil, false
	}
}
