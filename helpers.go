package latte

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/licenselatte/latte-go/internal/core/domain"
	"github.com/licenselatte/latte-go/internal/core/ports"
	"github.com/licenselatte/latte-go/internal/infra/crypto"
)

func parseAppID(appID string) (appEnv, string, error) {
	parts := strings.Split(appID, "_")
	if len(parts) != 3 || parts[0] != "pk" {
		return "", "", ErrInvalidAppID
	}

	env := appEnv(parts[1])
	if env != envLive && env != envTest && env != envLocal {
		return "", "", fmt.Errorf("%w: %s", ErrUnknownEnvironment, parts[1])
	}

	key := parts[2]
	if len(key) != 32 {
		return "", "", fmt.Errorf("%w: %s", ErrInvalidAppIDKeySegment, key)
	}
	if !crypto.ValidateKey(key, 4) {
		return "", "", ErrInvalidAppIDChecksum
	}

	return env, key, nil
}

func resolveStoragePath(appKey string) (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = "."
	}
	dir = filepath.Join(dir, "LicenseLatte")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		// Fall back to current directory.
		dir = ".licenselatte"
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
	}
	return filepath.Join(dir, appKey+".latte"), nil
}

func mapNetworkError(err error) error {
	switch {
	case errors.Is(err, ports.ErrLicenseInactiveOrExpired):
		return ErrLicenseExpired
	case errors.Is(err, ports.ErrSeatLimitReached):
		return ErrSeatLimit
	case errors.Is(err, ports.ErrInvalidProjectKey):
		return ErrInvalidProjectKey
	case errors.Is(err, ports.ErrLicenseNotFound):
		return ErrLicenseNotFound
	default:
		return err
	}
}

func domainToPublic(d *domain.License) *License {
	sinceActivation := time.Since(d.IssuedAt)
	inGracePeriod := sinceActivation > maxRenewalTime && sinceActivation < d.GracePeriod
	publicMetadata := make(map[string]string)
	if pmd, ok := d.Claims["pmd"]; ok {
		if pmdMap, ok := pmd.(map[string]interface{}); ok {
			for k, v := range pmdMap {
				if strVal, ok := v.(string); ok {
					publicMetadata[k] = strVal
				} else {
					fmt.Printf("Warning: pmd value for key %s is not a string\n", k)
				}
			}
		}
	}

	return &License{
		Key:           d.Key,
		ActivationID:  d.ActivationID,
		ProjectID:     d.ProjectID,
		LicenseType:   d.LicenseType,
		IssuedAt:      d.IssuedAt,
		ExpiresAt:     d.ExpiresAt,
		GracePeriod:   d.GracePeriod,
		InGracePeriod: inGracePeriod,
		Metadata:      publicMetadata,
	}
}
