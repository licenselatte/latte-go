package crypto

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/licenselatte/sdk-go/internal/core/ports"
)

type ed25519Validator struct {
	publicKey ed25519.PublicKey
	issuer    string
}

func NewEd25519Validator(publicKey ed25519.PublicKey, issuer string) ports.Validator {
	return &ed25519Validator{
		publicKey: publicKey,
		issuer:    issuer,
	}
}

func (v *ed25519Validator) Validate(t string, machineID string) (map[string]interface{}, error) {
	token, err := jwt.Parse(t, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("ed25519: verification error")
		}
		return v.publicKey, nil
	}, jwt.WithIssuer(v.issuer), jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}))

	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token: %v", err)
	}

	claims := token.Claims.(jwt.MapClaims)
	if claims["mid"] != machineID {
		return nil, errors.New("machine ID mismatch")
	}
	fmt.Printf("%+v\n%s\n", claims, machineID)

	lastCheck := int64(claims["iat"].(float64))
	gracePeriod := int64(claims["grc"].(float64))

	if time.Now().Unix() > lastCheck+gracePeriod {
		return nil, errors.New("token expired")
	}

	return claims, nil
}
