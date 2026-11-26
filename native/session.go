package dualwg

import (
	"errors"
	"strings"
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
	protected bool
	configured bool
	started bool
	configurationFailed bool
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
	if s.protected {
		// A failed IPC update may have partially changed the crypto device.
		// Never activate or reconfigure it; close and create a new session.
		if s.started || s.configured || s.configurationFailed { return ErrBadArgument }
		s.configurationFailed = true
		for _, line := range strings.Split(userspaceSettings, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "fwmark=") {
				return errExternalMark
			}
		}
	}
	if err := s.device.IpcSet(userspaceSettings); err != nil {
		return errors.New("WireGuard profile rejected")
	}
	s.configured = true
	s.configurationFailed = false
	return nil
}

func NewInactiveSession(name string, mtu, queueDepth int) (*Session, error) {
	memoryTun, err := NewPacketTun(name, mtu, queueDepth)
	if err != nil { return nil, err }
	logger := device.NewLogger(device.LogLevelSilent, "WonheeNative")
	cryptoDevice := device.NewDevice(memoryTun, conn.NewDefaultBind(), logger)
	return &Session{Tun: memoryTun, device: cryptoDevice}, nil
}

// NewProtectedSession prepares a separate userspace crypto device. This is
// not connected to Android yet: the caller must supply the actual owning
// VpnService's verified protect callback. No UDP socket opens in construction.
func NewProtectedSession(name string, mtu, queueDepth int, protector SocketProtector) (*Session, error) {
	if protector == nil { return nil, errProtection }
	memoryTun, err := NewPacketTun(name, mtu, queueDepth)
	if err != nil { return nil, err }
	logger := device.NewLogger(device.LogLevelSilent, "WonheeNative")
	cryptoDevice := device.NewDevice(memoryTun, newProtectedBind(conn.NewDefaultBind(),protector),logger)
	return &Session{Tun:memoryTun,device:cryptoDevice,protected:true},nil
}

// Start can only activate a successfully configured protected session.
// The Bind protects both actual UDP sockets on every Open before exposing
// them. No legacy inactive session can be activated through this method.
func (s *Session) Start() error {
	if s == nil {return ErrBadArgument}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {return ErrClosed}
	if !s.protected || !s.configured || s.configurationFailed || s.started {return ErrBadArgument}
	if err := s.device.Up(); err != nil {
		_ = s.device.Down()
		s.configurationFailed = true
		return errProtection
	}
	s.started = true
	return nil
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
