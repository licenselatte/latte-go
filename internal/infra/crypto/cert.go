package crypto

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const certIssuer = "licenselatte"

// VerifyCert verifies certJWT was signed by parentPub, evaluating time-based
// claims (iat/exp/nbf) as of now. Production callers pass time.Now(); tests
// pass a fixed instant so fixtures are reproducible regardless of wall clock.
func VerifyCert(parentPub ed25519.PublicKey, certJWT string, now time.Time) (jwt.MapClaims, error) {
	token, err := jwt.Parse(certJWT, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return parentPub, nil
	}, jwt.WithIssuedAt(), jwt.WithIssuer(certIssuer), jwt.WithTimeFunc(func() time.Time { return now }))
	if err != nil {
		return nil, err
	}
	mc, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("cert: invalid claims")
	}
	return mc, nil
}

// VerifyCertIgnoringExpiry is VerifyCert without the exp check: the cert must
// be signed by parentPub, carry the expected issuer and not be issued after
// now, but it may have expired. Callers bound what it signed by its window.
func VerifyCertIgnoringExpiry(parentPub ed25519.PublicKey, certJWT string, now time.Time) (jwt.MapClaims, error) {
	token, err := jwt.Parse(certJWT, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return parentPub, nil
	}, jwt.WithoutClaimsValidation())
	if err != nil {
		return nil, err
	}
	mc, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("cert: invalid claims")
	}
	// WithoutClaimsValidation skips the issuer and iat checks with the exp one.
	if iss, _ := mc["iss"].(string); iss != certIssuer {
		return nil, fmt.Errorf("cert: unexpected issuer %q", iss)
	}
	iat, err := mc.GetIssuedAt()
	if err != nil || iat == nil {
		return nil, errors.New("cert: missing iat")
	}
	if iat.After(now) {
		return nil, errors.New("cert: used before issued")
	}
	return mc, nil
}

func PubKeyFromCert(claims jwt.MapClaims, pubField string) (ed25519.PublicKey, error) {
	raw, ok := claims[pubField].(string)
	if !ok {
		return nil, fmt.Errorf("cert: missing %q field", pubField)
	}
	b, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("cert: %q is not valid hex: %w", pubField, err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("cert: %q must be %d bytes, got %d", pubField, ed25519.PublicKeySize, len(b))
	}
	return ed25519.PublicKey(b), nil
}
