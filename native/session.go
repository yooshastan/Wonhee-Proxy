package dualwg

import (
	"errors"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

// Session owns a genuine, independent WireGuard userspace crypto device.
// It remains DOWN; a protected Android UDP bind and JNI packet I/O must exist
// before we can safely Up() or accept real user credentials/configuration.
type Session struct {
	Tun    *PacketTun
	device *device.Device
	mu     sync.Mutex
	closed bool
}

// Configure loads one wireguard-go userspace-format profile into its own
// crypto device. The Android parser will supply toWgUserspaceString() from
// each independently sealed profile. Do not log or return the raw settings.
// Sessions remain DOWN; socket protection is not yet implemented.
func (s *Session) Configure(userspaceSettings string) error {
	if s == nil || len(userspaceSettings) < 1 || len(userspaceSettings) > 65536 {
		return ErrBadArgument
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed { return ErrClosed }
	if err := s.device.IpcSet(userspaceSettings); err != nil {
		return errors.New("WireGuard profile rejected")
	}
	return nil
}

func NewInactiveSession(name string, mtu, queueDepth int) (*Session, error) {
	memoryTun, err := NewPacketTun(name, mtu, queueDepth)
	if err != nil { return nil, err }
	logger := device.NewLogger(device.LogLevelSilent, "WonheeNative")
	cryptoDevice := device.NewDevice(memoryTun, conn.NewDefaultBind(), logger)
	return &Session{Tun: memoryTun, device: cryptoDevice}, nil
}

// Close is idempotent and releases all crypto workers and queued packet I/O.
func (s *Session) Close() {
	if s == nil { return }
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed { return }
	s.closed = true
	s.device.Close()
	s.Tun.Close()
}
