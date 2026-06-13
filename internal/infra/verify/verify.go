package verify

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/licenselatte/latte-go/internal/core/domain"
	llcrypto "github.com/licenselatte/latte-go/internal/infra/crypto"
)

const (
	issuer = "licenselatte"
)

func VerifyActivation(masterPub ed25519.PublicKey, token string, chain *domain.CertChain) (*domain.License, error) {
	// Step 1: Verify submaster cert (signed by master).
	subClaims, err := llcrypto.VerifyCert(masterPub, chain.Submaster)
	if err != nil {
		return nil, fmt.Errorf("verify: submaster cert invalid: %w", err)
	}
	submasterPub, err := llcrypto.PubKeyFromCert(subClaims, "spk")
	if err != nil {
		return nil, fmt.Errorf("verify: submaster cert missing spk: %w", err)
	}

	// Step 2: Verify project cert (signed by submaster).
	projClaims, err := llcrypto.VerifyCert(submasterPub, chain.Project)
	if err != nil {
		return nil, fmt.Errorf("verify: project cert invalid: %w", err)
	}
	projectPub, err := llcrypto.PubKeyFromCert(projClaims, "ppk")
	if err != nil {
		return nil, fmt.Errorf("verify: project cert missing ppk: %w", err)
	}

	// Step 3: Verify daily cert (signed by project key).
	dailyClaims, err := llcrypto.VerifyCert(projectPub, chain.Daily)
	if err != nil {
		return nil, fmt.Errorf("verify: daily cert invalid: %w", err)
	}
	dailyPub, err := llcrypto.PubKeyFromCert(dailyClaims, "dpk")
	if err != nil {
		return nil, fmt.Errorf("verify: daily cert missing dpk: %w", err)
	}

	// Step 4: Verify activation JWT (signed by daily key).
	parsed, err := jwt.Parse(token,
		func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodEd25519); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return dailyPub, nil
		},
		jwt.WithIssuedAt(),
		jwt.WithIssuer(issuer),
		// We handle expiry ourselves; passing a large leeway effectively disables
		// the library's exp check without losing the rest of the validation.
		jwt.WithLeeway(100*365*24*time.Hour),
	)

	if err != nil {
		return nil, fmt.Errorf("verify: activation JWT invalid: %w", err)
	}

	mc, ok := parsed.Claims.(jwt.MapClaims)
	if !ok || !parsed.Valid {
		return nil, fmt.Errorf("verify: activation JWT claims invalid")
	}

	claims := &domain.License{
		Key:           stringClaim(mc, "sub"),
		ActivationID:  stringClaim(mc, "aid"),
		ProjectID:     stringClaim(mc, "pid"),
		MachineIDHash: stringClaim(mc, "mid"),
		LicenseType:   stringClaim(mc, "ltype"),
		Claims:        mc,
	}

	if grc, ok := mc["grc"].(float64); ok {
		claims.GracePeriod = time.Duration(int64(grc)) * time.Second
	}
	if iat, ok := mc["iat"].(float64); ok {
		claims.IssuedAt = time.Unix(int64(iat), 0)
	}
	if exp, ok := mc["exp"].(float64); ok {
		claims.ExpiresAt = time.Unix(int64(exp), 0)
	}

	// Cross-check: project_id in activation JWT must match project_id in project cert.
	if pidInCert, _ := projClaims["pid"].(string); pidInCert != "" && pidInCert != claims.ProjectID {
		return nil, fmt.Errorf("verify: project_id mismatch between JWT (%s) and project cert (%s)", claims.ProjectID, pidInCert)
	}

	dailyIat, ok := dailyClaims["iat"].(float64)
	if !ok {
		return nil, fmt.Errorf("verify: daily cert missing iat claim")
	}
	dailyIatTime := time.Unix(int64(dailyIat), 0)

	// Cross-check: activation JWT iat must be after daily cert iat.
	if claims.IssuedAt.Before(dailyIatTime) {
		return nil, fmt.Errorf("verify: activation JWT iat (%s) is before daily cert iat (%s)", claims.IssuedAt, dailyIatTime)
	}

	dailyExp, ok := dailyClaims["exp"].(float64)
	if !ok {
		return nil, fmt.Errorf("verify: daily cert missing exp claim")
	}
	dailyExpTime := time.Unix(int64(dailyExp), 0)

	// Cross-check: activation JWT exp must be before daily cert exp.
	if claims.ExpiresAt.After(dailyExpTime) {
		return nil, fmt.Errorf("verify: activation JWT exp (%s) is after daily cert exp (%s)", claims.ExpiresAt, dailyExpTime)
	}

	return claims, nil
}

func stringClaim(mc jwt.MapClaims, key string) string {
	if v, ok := mc[key].(string); ok {
		return v
	}
	return ""
}
