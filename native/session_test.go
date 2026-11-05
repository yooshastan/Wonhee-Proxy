package dualwg

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestTwoIndependentCryptoDevices(t *testing.T) {
	home, err := NewInactiveSession("home", 1280, 2)
	if err != nil { t.Fatal(err) }
	defer home.Close()
	exit, err := NewInactiveSession("airvpn", 1280, 2)
	if err != nil { t.Fatal(err) }
	defer exit.Close()
	if home.device == exit.device || home.Tun == exit.Tun { t.Fatal("sessions shared state") }
	if home.device == nil || exit.device == nil { t.Fatal("missing real crypto devices") }
	if err := home.Tun.Inject([]byte{0x45, 1, 2, 3}); err != nil { t.Fatal(err) }
	bufs := [][]byte{make([]byte, 256)}
	sizes := make([]int, 1)
	n, err := home.Tun.Read(bufs, sizes, 8)
	if err != nil || n != 1 || sizes[0] != 4 || !bytes.Equal(bufs[0][8:12], []byte{0x45, 1, 2, 3}) {
		t.Fatal("home virtual TUN did not read its own packet")
	}
	// The independent Internet queue must not receive Home packets.
	if packet, ok := exit.Tun.Poll(); ok || packet != nil { t.Fatal("cross-tunnel traffic") }
	home.Close()
	if err := home.Tun.Inject([]byte{1}); !errors.Is(err, ErrClosed) { t.Fatalf("post-close inject: %v", err) }
	if _, err := home.Tun.Read(bufs, sizes, 0); !errors.Is(err, io.EOF) { t.Fatalf("post-close read: %v", err) }
}

func TestQueueIsolationAndBackpressure(t *testing.T) {
	tun, err := NewPacketTun("test", 1280, 1)
	if err != nil { t.Fatal(err) }
	defer tun.Close()
	packet := []byte{1, 2, 3}
	if err := tun.Inject(packet); err != nil { t.Fatal(err) }
	packet[0] = 9
	if err := tun.Inject([]byte{4}); !errors.Is(err, ErrQueueFull) { t.Fatalf("expected drop, got %v", err) }
	bufs := [][]byte{make([]byte, 32)}
	sizes := make([]int, 1)
	n, err := tun.Read(bufs, sizes, 0)
	if err != nil || n != 1 || sizes[0] != 3 || !bytes.Equal(bufs[0][:3], []byte{1, 2, 3}) { t.Fatal("inject copied incorrectly") }
	decrypted := []byte{4, 5, 6}
	if count, err := tun.Write([][]byte{decrypted}, 0); count != 1 || err != nil { t.Fatalf("write: %d %v", count, err) }
	decrypted[0] = 99
	if count, err := tun.Write([][]byte{{7}}, 0); count != 0 || !errors.Is(err, ErrQueueFull) { t.Fatalf("expected bounded queue: %d %v", count, err) }
	got, ok := tun.Poll()
	if !ok || !bytes.Equal(got, []byte{4, 5, 6}) { t.Fatal("decrypted data not isolated") }
	if _, ok = tun.Poll(); ok { t.Fatal("unexpected second packet") }
}

func TestInvalidTunRejected(t *testing.T) {
	for _, args := range []struct{name string; mtu, depth int}{
		{"", 1280, 8}, {"thisnameiswaytoolong", 1280, 8}, {"ok", 0, 8},
		{"ok", 1280, 0}, {"ok", 1280, 5000},
	} {
		if _, err := NewPacketTun(args.name, args.mtu, args.depth); err == nil { t.Fatalf("accepted invalid %+v", args) }
	}
}
