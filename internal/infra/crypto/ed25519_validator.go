package crypto

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/licenselatte/latte-go/internal/core/domain"
	"github.com/licenselatte/latte-go/internal/core/ports"
)

const certIssuer = "licenselatte"

type ed25519Validator struct {
	publicKey ed25519.PublicKey
	issuer    string
}

func NewEd25519Validator(publicKey ed25519.PublicKey, issuer string) ports.Validator {
	return &ed25519Validator{publicKey: publicKey, issuer: issuer}
}

func (v *ed25519Validator) Validate(raw string, machineID string) (*domain.License, error) {
	// Parse and verify signature + issuer. We disable the automatic exp check so
	// we can apply the grc-based offline logic ourselves below.
	token, err := jwt.Parse(raw,
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return v.publicKey, nil
		},
		jwt.WithIssuer(v.issuer),
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		// We handle expiry ourselves; passing a large leeway effectively disables
		// the library's exp check without losing the rest of the validation.
		jwt.WithLeeway(100*365*24*time.Hour),
	)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	// Machine ID must match the current device.
	mid, _ := claims["mid"].(string)
	if mid != machineID {
		return nil, errors.New("machine ID mismatch")
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, errors.New("token missing exp claim")
	}
	expTime := time.Unix(int64(exp), 0)

	iat, ok := claims["iat"].(float64)
	if !ok {
		return nil, errors.New("token missing iat claim")
	}
	iatTime := time.Unix(int64(iat), 0)

	// perpetual_fixed tokens never expire and have no grc check.
	// The only requirement is that we haven't somehow passed year 2099.
	ltype, _ := claims["ltype"].(string)
	if ltype == "perpetual_fixed" {
		if time.Now().After(expTime) {
			return nil, ports.ErrLicenseInactiveOrExpired
		}
		return buildLicense(claims, expTime, iatTime, 0), nil
	}

	// For all other license types:
	//
	// grc  = offline grace window in seconds from iat (last successful issuance/renewal).
	// rule : iat + grc > exp  → collision (grace window extends past license expiry) → expired.
	//        now > iat + grc  → offline too long, must reconnect.
	//
	// Corollary: if both checks pass, now ≤ iat+grc ≤ exp, the license is valid.
	grc, _ := claims["grc"].(float64)
	graceWindow := time.Duration(int64(grc)) * time.Second
	offlineDeadline := iatTime.Add(graceWindow)

	if offlineDeadline.After(expTime) {
		// Grace window collides with license expiry, treat as expired.
		return nil, ports.ErrLicenseInactiveOrExpired
	}

	now := time.Now()
	if now.After(expTime) {
		return nil, ports.ErrLicenseInactiveOrExpired
	}
	if now.After(offlineDeadline) {
		return nil, ports.ErrGracePeriodExpired
	}

	return buildLicense(claims, expTime, iatTime, graceWindow), nil
}

func buildLicense(claims jwt.MapClaims, expTime time.Time, iatTime time.Time, grace time.Duration) *domain.License {
	key, _ := claims["sub"].(string)
	aid, _ := claims["aid"].(string)
	pid, _ := claims["pid"].(string)
	ltype, _ := claims["ltype"].(string)
	return &domain.License{
		Key:          key,
		ActivationID: aid,
		ProjectID:    pid,
		LicenseType:  ltype,
		IssuedAt:     iatTime,
		ExpiresAt:    expTime,
		GracePeriod:  grace,
		Claims:       map[string]interface{}(claims),
	}
}

func VerifyCert(parentPub ed25519.PublicKey, certJWT string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(certJWT, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return parentPub, nil
	}, jwt.WithIssuedAt(), jwt.WithIssuer(certIssuer))
	if err != nil {
		return nil, err
	}
	mc, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("cert: invalid claims")
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
