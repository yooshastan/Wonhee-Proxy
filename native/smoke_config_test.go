package dualwg

import (
	"encoding/hex"
	"strings"
	"testing"
)

type smokeNoProtect struct{}
func (smokeNoProtect) Protect(int) bool { return false }

func TestActualJNISmokeConfigAcceptedByWireGuard(t *testing.T) {
	seen := map[string]bool{}
	for _, name := range []string{"home", "internet"} {
		config, err := NewEphemeralSmokeConfig()
		if err != nil { t.Fatal("temporary key generation failed") }
		lines := strings.Split(strings.TrimSuffix(config, "\n"), "\n")
		if len(lines) != 4 || lines[1] != "replace_peers=true" || lines[3] != "allowed_ip=192.0.2.0/24" {
			t.Fatal("unexpected smoke profile fields")
		}
		for _, entry := range []struct{ index int; prefix string }{{0,"private_key="},{2,"public_key="}} {
			line := lines[entry.index]
			if !strings.HasPrefix(line,entry.prefix) { t.Fatal("missing key") }
			key := strings.TrimPrefix(line,entry.prefix)
			raw, err := hex.DecodeString(key)
			if err != nil || len(raw) != 32 || len(key) != 64 || seen[key] {
				t.Fatal("invalid or repeated ephemeral key")
			}
			seen[key] = true
		}
		s, err := NewProtectedSession(name,1280,32,smokeNoProtect{})
		if err != nil { t.Fatal("protected session construction failed") }
		if err = s.Configure(config); err != nil {
			s.Close()
			t.Fatal("actual JNI smoke configuration rejected by wireguard-go")
		}
		// Host CI tests the exact production IPC parser path, not Android protect.
		// Do not activate a host session or open sockets here.
		s.Close()
	}
}
