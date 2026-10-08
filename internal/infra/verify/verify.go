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
	issuer         = "licenselatte"
	maxGracePeriod = 90 * 24 * time.Hour
)

// noExpiry is ExpiresAt for a licence with no end date. It matches the exp a
// grc-format perpetual token carries, so a perpetual licence reports the same
// ExpiresAt in either token format.
var noExpiry = time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)

// VerifyActivation verifies the chain against masterPubs, the trusted root
// keys: the submaster cert must be signed by any one of them.
func VerifyActivation(masterPubs []ed25519.PublicKey, token string, chain *domain.CertChain) (*domain.License, error) {
	return VerifyActivationAnyAt(masterPubs, token, chain, time.Now())
}

// VerifyActivationAt is VerifyActivationAnyAt with a single root key, so tests
// can replay the shared testdata/ fixtures (each pinned to a fixed instant and
// carrying its own master key) without depending on the real wall clock.
// Production code should call VerifyActivation; this exists purely as a test
// seam.
func VerifyActivationAt(masterPub ed25519.PublicKey, token string, chain *domain.CertChain, now time.Time) (*domain.License, error) {
	return VerifyActivationAnyAt([]ed25519.PublicKey{masterPub}, token, chain, now)
}

// VerifyActivationAnyAt is VerifyActivation with an injectable clock.
func VerifyActivationAnyAt(masterPubs []ed25519.PublicKey, token string, chain *domain.CertChain, now time.Time) (*domain.License, error) {
	// Step 1: Verify submaster cert (signed by any trusted master).
	var subClaims jwt.MapClaims
	err := fmt.Errorf("no master keys")
	for _, masterPub := range masterPubs {
		if subClaims, err = llcrypto.VerifyCert(masterPub, chain.Submaster, now); err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("verify: submaster cert invalid: %w", err)
	}
	submasterPub, err := llcrypto.PubKeyFromCert(subClaims, "spk")
	if err != nil {
		return nil, fmt.Errorf("verify: submaster cert missing spk: %w", err)
	}

	// Step 2: Verify project cert (signed by submaster).
	projClaims, err := llcrypto.VerifyCert(submasterPub, chain.Project, now)
	if err != nil {
		return nil, fmt.Errorf("verify: project cert invalid: %w", err)
	}
	projectPub, err := llcrypto.PubKeyFromCert(projClaims, "ppk")
	if err != nil {
		return nil, fmt.Errorf("verify: project cert missing ppk: %w", err)
	}

	// Step 3: Verify daily cert (signed by project key).
	// The daily cert is not checked against now: it expires the morning after
	// it is issued, and the token it signed has to verify offline for its whole
	// grace period. Its window bounds the token's iat instead, below.
	dailyClaims, err := llcrypto.VerifyCertIgnoringExpiry(projectPub, chain.Daily, now)
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
		// exp is enforced by validate, which reports it as hard_expired or
		// grace_expired depending on the format. The large leeway disables the
		// library's exp check without losing the rest of the validation.
		jwt.WithLeeway(100*365*24*time.Hour),
		jwt.WithTimeFunc(func() time.Time { return now }),
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
		Alias:         stringClaim(mc, "alias"),
		ActivationID:  stringClaim(mc, "aid"),
		ProjectID:     stringClaim(mc, "pid"),
		MachineIDHash: stringClaim(mc, "mid"),
		LicenseType:   stringClaim(mc, "ltype"),
		Claims:        mc,
	}

	if iat, ok := mc["iat"].(float64); ok {
		claims.IssuedAt = time.Unix(int64(iat), 0)
	}
	exp, hasExp := mc["exp"].(float64)
	if _, ok := mc["grc"]; ok {
		// grc format: exp is the licence's end, grc the offline window from iat.
		grc, _ := mc["grc"].(float64)
		claims.GracePeriod = time.Duration(int64(grc)) * time.Second
		if hasExp {
			claims.ExpiresAt = time.Unix(int64(exp), 0)
		}
	} else {
		// lex format: exp is the offline deadline itself and lex, when
		// present, the licence's end. Either way validate sees the offline
		// deadline as IssuedAt+GracePeriod and the licence's end as ExpiresAt.
		claims.ExpiresAt = noExpiry
		if lex, ok := mc["lex"].(float64); ok {
			claims.ExpiresAt = time.Unix(int64(lex), 0)
		}
		if hasExp {
			claims.GracePeriod = time.Unix(int64(exp), 0).Sub(claims.IssuedAt)
		}
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

	// Cross-check: activation JWT iat must be before daily cert exp, so a daily
	// key cannot sign tokens dated after its own day.
	if claims.IssuedAt.After(dailyExpTime) {
		return nil, fmt.Errorf("verify: activation JWT iat (%s) is after daily cert exp (%s)", claims.IssuedAt, dailyExpTime)
	}

	if claims.GracePeriod > maxGracePeriod {
		return nil, fmt.Errorf("verify: grace period too long: %s", claims.GracePeriod)
	}

	return claims, nil
}

func stringClaim(mc jwt.MapClaims, key string) string {
	if v, ok := mc[key].(string); ok {
		return v
	}
	return ""
}
