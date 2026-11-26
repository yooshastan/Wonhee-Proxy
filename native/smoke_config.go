package dualwg

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
)

// NewEphemeralSmokeConfig uses the original WireGuard userspace IPC test route.
func NewEphemeralSmokeConfig() (string, error) {
	return NewEphemeralSmokeConfigForAllowedIP("192.0.2.0/24")
}

// NewEphemeralSmokeConfigForAllowedIP creates a temporary-key, no-endpoint
// profile for the debug packet-pump experiment. Only exact synthetic routes
// used by that test are accepted; user-provided routes never enter this path.
func NewEphemeralSmokeConfigForAllowedIP(allowedIP string) (string, error) {
	switch allowedIP {
	case "192.0.2.0/24", "198.18.1.0/24", "0.0.0.0/0":
	default:
		return "", ErrBadArgument
	}
	curve := ecdh.X25519()
	private, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	peer, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("private_key=%x\nreplace_peers=true\npublic_key=%x\nallowed_ip=%s\n",
		private.Bytes(), peer.PublicKey().Bytes(), allowedIP), nil
}
