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
		s.Close()
	}
}

func TestPacketPumpSmokeConfigsAreExactAndAccepted(t *testing.T) {
	for _, route := range []string{"198.18.1.0/24", "0.0.0.0/0"} {
		config, err := NewEphemeralSmokeConfigForAllowedIP(route)
		if err != nil { t.Fatal("synthetic route config rejected") }
		if !strings.Contains(config, "allowed_ip="+route+"\n")
			|| strings.Contains(config, "endpoint=")
			|| strings.Contains(config, "dns=") {
			t.Fatal("packet-pump config contains unexpected fields")
		}
		session, err := NewProtectedSession("packet", 1280, 8, smokeNoProtect{})
		if err != nil { t.Fatal("protected session construction failed") }
		if err := session.Configure(config); err != nil {
			session.Close()
			t.Fatal("packet-pump config rejected by wireguard-go IPC parser")
		}
		session.Close()
	}
	for _, route := range []string{"198.18.0.0/15", "10.0.0.0/8", "::/0", "0.0.0.0/0,::/0", ""} {
		if _, err := NewEphemeralSmokeConfigForAllowedIP(route); err == nil {
			t.Fatalf("unapproved synthetic route accepted: %q", route)
		}
	}
}
