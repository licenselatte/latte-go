package latte

import (
	"bytes"
	"encoding/hex"
	"testing"

	"filippo.io/edwards25519"
)

// TestMasterPublicKeysArePrimeOrder checks that every embedded root is the
// canonical encoding of a point of prime order L: P is not the identity and
// [L]P is. latte-c verifies with Monocypher, which cannot run this check, so
// its tests/test_anchors.c pins the same keys byte for byte and points here:
// a new or changed root has to pass this test first.
func TestMasterPublicKeysArePrimeOrder(t *testing.T) {
	// L - 1, little-endian. [L]P is computed as [L-1]P + P because L itself
	// is not a canonical scalar.
	lMinus1, _ := hex.DecodeString("ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
	s, err := edwards25519.NewScalar().SetCanonicalBytes(lMinus1)
	if err != nil {
		t.Fatal(err)
	}
	primeOrder := func(p *edwards25519.Point) bool {
		lp := new(edwards25519.Point).ScalarMult(s, p)
		lp.Add(lp, p)
		id := edwards25519.NewIdentityPoint()
		return p.Equal(id) == 0 && lp.Equal(id) == 1
	}

	// A point of order 8: added to a root, the sum must fail the check.
	t8Bytes, _ := hex.DecodeString("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")
	t8, err := new(edwards25519.Point).SetBytes(t8Bytes)
	if err != nil {
		t.Fatal(err)
	}

	for _, h := range masterPublicKeysHex {
		b, _ := hex.DecodeString(h)
		p, err := new(edwards25519.Point).SetBytes(b)
		if err != nil {
			t.Errorf("%s: not a point on the curve", h)
			continue
		}
		if !bytes.Equal(p.Bytes(), b) {
			t.Errorf("%s: not a canonical encoding", h)
		}
		if !primeOrder(p) {
			t.Errorf("%s: not of prime order L", h)
		}
		if primeOrder(new(edwards25519.Point).Add(p, t8)) {
			t.Errorf("%s: the check accepted the key plus a point of order 8", h)
		}
	}
}
