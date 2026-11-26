package dualwg

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
)

// NewEphemeralSmokeConfig uses the actual WireGuard userspace IPC format:
// 32-byte keys encoded as 64 hex characters, not wg-quick Base64.
// This generated configuration intentionally has no peer endpoint, DNS,
// keepalive, or user credentials. Never log the returned private key.
func NewEphemeralSmokeConfig() (string, error) {
	curve := ecdh.X25519()
	private, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	peer, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("private_key=%x\nreplace_peers=true\npublic_key=%x\nallowed_ip=192.0.2.0/24\n",
		private.Bytes(), peer.PublicKey().Bytes()), nil
}
