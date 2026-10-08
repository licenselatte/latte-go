package verify

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/licenselatte/latte-go/internal/core/domain"
	llcrypto "github.com/licenselatte/latte-go/internal/infra/crypto"
)

// chainFor builds a chain the way the server does: 180-day submaster and
// project certs, and a daily cert valid from 00:00 UTC on day to 00:05 UTC
// the next day, which signs an activation token issued at iat.
func chainFor(t *testing.T, day, iat time.Time, grace time.Duration) (ed25519.PublicKey, string, *domain.CertChain) {
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
	masterPub, masterPriv := gen()
	subPub, subPriv := gen()
	projPub, projPriv := gen()
	dailyPub, dailyPriv := gen()

	certStart := day.AddDate(0, 0, -30)
	certEnd := certStart.AddDate(0, 0, 180)
	chain := &domain.CertChain{
		Submaster: sign(masterPriv, jwt.MapClaims{
			"sub": "submaster", "spk": hex.EncodeToString(subPub),
			"iat": certStart.Unix(), "exp": certEnd.Unix(),
		}),
		Project: sign(subPriv, jwt.MapClaims{
			"sub": "project", "pid": "proj", "ppk": hex.EncodeToString(projPub),
			"iat": certStart.Unix(), "exp": certEnd.Unix(),
		}),
		Daily: sign(projPriv, jwt.MapClaims{
			"sub": "daily", "pid": "proj", "dpk": hex.EncodeToString(dailyPub),
			"day": day.Format("2006-01-02"),
			"iat": day.Unix(), "exp": day.AddDate(0, 0, 1).Add(5 * time.Minute).Unix(),
		}),
	}
	token := sign(dailyPriv, jwt.MapClaims{
		"sub": "KEY", "aid": "act", "pid": "proj", "mid": "machine", "ltype": "perpetual",
		"iat": iat.Unix(), "exp": iat.AddDate(1, 0, 0).Unix(), "grc": int64(grace / time.Second),
	})
	return masterPub, token, chain
}

// A cached token must keep verifying offline for its whole grace period. The
// daily cert that signed it expires the next morning, so verification must
// not hold the daily cert's exp against the current time.
func TestVerifyActivation_OfflineAcrossDayBoundary(t *testing.T) {
	day := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
	iat := day.Add(23*time.Hour + 59*time.Minute) // activated at 23:59 UTC
	masterPub, token, chain := chainFor(t, day, iat, 30*24*time.Hour)

	for _, offline := range []time.Duration{time.Minute, 10 * time.Minute, 24 * time.Hour, 29 * 24 * time.Hour} {
		if _, err := VerifyActivationAt(masterPub, token, chain, iat.Add(offline)); err != nil {
			t.Errorf("offline %s after activation: %v", offline, err)
		}
	}
}

// What the daily cert does bound: a token whose iat falls outside the daily
// cert's window is rejected whatever the current time, so a leaked daily key
// cannot sign tokens dated after its own day.
func TestVerifyActivation_TokenOutsideDailyWindowRejected(t *testing.T) {
	day := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
	for _, iat := range []time.Time{day.Add(-time.Minute), day.AddDate(0, 0, 1).Add(6 * time.Minute)} {
		masterPub, token, chain := chainFor(t, day, iat, 30*24*time.Hour)
		if _, err := VerifyActivationAt(masterPub, token, chain, iat.Add(time.Minute)); err == nil {
			t.Errorf("token with iat %s outside daily window was accepted", iat)
		}
	}
}

func TestVerifyCertIgnoringExpiry_RejectsWrongIssuer(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	s, _ := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{"iss": "someone-else", "iat": time.Now().Add(-time.Hour).Unix()}).SignedString(priv)
	if _, err := llcrypto.VerifyCertIgnoringExpiry(pub, s, time.Now()); err == nil {
		t.Fatal("cert from another issuer was accepted")
	}
}

func TestVerifyCertIgnoringExpiry_RejectsFutureIat(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	s, _ := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{"iss": issuer, "iat": time.Now().Add(time.Hour).Unix()}).SignedString(priv)
	if _, err := llcrypto.VerifyCertIgnoringExpiry(pub, s, time.Now()); err == nil {
		t.Fatal("cert issued in the future was accepted")
	}
}
