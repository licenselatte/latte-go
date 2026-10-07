package latte

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

func TestMasterPublicKeysHex(t *testing.T) {
	seen := map[string]bool{}
	for _, h := range masterPublicKeysHex {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != ed25519.PublicKeySize {
			t.Errorf("%s: not a %d-byte hex key", h, ed25519.PublicKeySize)
		}
		if seen[h] {
			t.Errorf("%s: listed twice", h)
		}
		seen[h] = true
	}
	if got := len(masterPublicKeys()); got != len(masterPublicKeysHex) {
		t.Errorf("decoded %d keys, want %d", got, len(masterPublicKeysHex))
	}
}
