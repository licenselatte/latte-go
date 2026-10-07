package verify

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/licenselatte/latte-go/internal/core/domain"
)

// chainSignedBy builds a valid chain and token whose submaster cert is signed
// by root.
func chainSignedBy(t *testing.T, root ed25519.PrivateKey, now time.Time) (string, *domain.CertChain) {
	t.Helper()
	gen := func() (ed25519.PublicKey, ed25519.PrivateKey) {
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		return pub, priv
	}
	sign := func(priv ed25519.PrivateKey, claims jwt.MapClaims) string {
		claims["iss"] = issuer
		s, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(priv)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	subPub, subPriv := gen()
	projPub, projPriv := gen()
	dailyPub, dailyPriv := gen()
	from, to := now.Add(-time.Hour).Unix(), now.Add(time.Hour).Unix()

	chain := &domain.CertChain{
		Submaster: sign(root, jwt.MapClaims{"sub": "submaster", "spk": hex.EncodeToString(subPub), "iat": from, "exp": to}),
		Project:   sign(subPriv, jwt.MapClaims{"sub": "project", "pid": "proj", "ppk": hex.EncodeToString(projPub), "iat": from, "exp": to}),
		Daily:     sign(projPriv, jwt.MapClaims{"sub": "daily", "pid": "proj", "dpk": hex.EncodeToString(dailyPub), "iat": from, "exp": to}),
	}
	token := sign(dailyPriv, jwt.MapClaims{
		"sub": "KEY", "aid": "act", "pid": "proj", "mid": "machine", "ltype": "perpetual",
		"iat": now.Unix(), "exp": now.Add(24 * time.Hour).Unix(), "grc": int64(3600),
	})
	return token, chain
}

func TestVerifyActivationAnyAt_AnyTrustedRoot(t *testing.T) {
	now := time.Now()
	var anchors []ed25519.PublicKey
	var roots []ed25519.PrivateKey
	for i := 0; i < 3; i++ {
		pub, priv, _ := ed25519.GenerateKey(nil)
		anchors, roots = append(anchors, pub), append(roots, priv)
	}

	for i, root := range roots {
		token, chain := chainSignedBy(t, root, now)
		if _, err := VerifyActivationAnyAt(anchors, token, chain, now); err != nil {
			t.Errorf("chain signed by anchor %d rejected: %v", i, err)
		}
	}

	_, outsider, _ := ed25519.GenerateKey(nil)
	token, chain := chainSignedBy(t, outsider, now)
	if _, err := VerifyActivationAnyAt(anchors, token, chain, now); err == nil {
		t.Error("chain signed by a key outside the list was accepted")
	}
	if _, err := VerifyActivationAnyAt(nil, token, chain, now); err == nil {
		t.Error("chain accepted with no trusted keys")
	}
}
