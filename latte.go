// Package latte is the Go client SDK for LicenseLatte.
//
// Typical usage:
//
//	sdk, err := latte.New(&latte.Config{AppID: "pk_live_..."})
//	if err != nil { /* bad config */ }
//
//	license, err := sdk.Activate(licenseKey)
//	if err != nil { /* handle: ErrLicenseExpired, ErrSeatLimit, etc. */ }
//
//	// Periodically (e.g. on startup, every N minutes):
//	license, err = sdk.Check()
package latte

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/denisbrodbeck/machineid"
	"github.com/licenselatte/latte-go/internal/core/domain"
	"github.com/licenselatte/latte-go/internal/core/ports"
	"github.com/licenselatte/latte-go/internal/infra/crypto"
	latthttp "github.com/licenselatte/latte-go/internal/infra/http"
	"github.com/licenselatte/latte-go/internal/infra/storage"
	"github.com/licenselatte/latte-go/internal/infra/validate"
	"github.com/licenselatte/latte-go/internal/infra/verify"
)

type Config struct {
	// AppID is the project key shown in the LicenseLatte dashboard (pk_live_… / pk_test_… / pk_local_…).
	AppID string
}

// SDK is the main entry point. Create one instance per application.
type SDK struct {
	appID            string
	appKey           string // 32-char portion after "pk_{env}_"
	activator        ports.Activator
	renewer          ports.Renewer
	store            ports.Storage
	machineID        string
	renewMu          sync.Mutex
	lastRenewAttempt time.Time
	renewInFlight    bool
	pubKey           ed25519.PublicKey
}

// New creates a new SDK instance. Returns an error if AppID is invalid or
// the local token-storage directory cannot be created.
func New(config *Config) (*SDK, error) {
	env, appKey, err := parseAppID(config.AppID)
	if err != nil {
		return nil, err
	}

	var apiURL string
	switch env {
	case envTest:
		apiURL = testURL
	case envLive:
		apiURL = publicURL
	case envLocal:
		apiURL = localURL
	}

	client := latthttp.NewHttpClient(apiURL, config.AppID)

	pubKeyBytes, _ := hex.DecodeString(publicKeyHex)

	storePath, err := resolveStoragePath(appKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStorageInitFailed, err)
	}

	machineID, err := machineid.ProtectedID(fmt.Sprintf("licenselatte_" + config.AppID))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMachineIDFailed, err)
	}

	return &SDK{
		appID:     config.AppID,
		appKey:    appKey,
		activator: client,
		renewer:   client,
		store:     storage.NewFileStorage(storePath),
		machineID: machineID,
		pubKey:    pubKeyBytes,
	}, nil
}

// Activate validates the license key and activates this machine.
//
// On the happy path it returns a *License immediately from the local token cache.
// If no valid cached token exists, it calls the LicenseLatte API to activate.
// A background goroutine silently renews the token whenever a valid cache hit occurs,
// so the local copy stays fresh.
func (s *SDK) Activate(key string) (*License, error) {
	return s.ActivateWithContext(context.Background(), key)
}

// ActivateWithContext is the context-aware version of Activate.
func (s *SDK) ActivateWithContext(ctx context.Context, rawKey string) (*License, error) {
	key := crypto.SanitizeKey(rawKey)
	normalized := crypto.NormalizeKey(rawKey)
	if err := s.validateLicenseKey(normalized); err != nil {
		return nil, err
	}

	// Fast path: valid cached token.
	if raw, chain, err := s.store.LoadToken(); err == nil {
		if lic, err := verify.VerifyActivation(s.pubKey, raw, chain); err == nil {
			if err := validate.Validate(lic, s.machineID); err == nil {
				if s.shouldTryRenew(lic) {
					// Renew in the background so it's fresh next time.
					go s.silentRenew(lic)
				}

				// lic.Key is the JWT sub claim: for a native-format key
				// that's the same string activated with, but for a
				// license resolved via a legacy-key alias it's the
				// newly minted native key instead — the customer's app
				// keeps passing the original legacy string forever, so
				// that case is matched against lic.Alias (the JWT's
				// alias claim) instead.
				matches := lic.Key == key || (lic.Alias != "" && lic.Alias == normalized)
				if matches && lic.IsValid() {
					return domainToPublic(lic), nil
				}
			}
		}
	}

	// Cache miss or expired: activate via network.
	raw, chain, err := s.activator.Activate(ctx, normalized, s.machineID)
	if err != nil {
		return nil, mapNetworkError(err)
	}

	lic, err := verify.VerifyActivation(s.pubKey, raw, chain)
	if err != nil {
		return nil, fmt.Errorf("licenselatte: server returned invalid token: %w", err)
	}

	err = validate.Validate(lic, s.machineID)
	if err != nil {
		return nil, fmt.Errorf("licenselatte: server returned invalid token: %w", err)
	}

	_ = s.store.SaveToken(raw, chain)

	return domainToPublic(lic), nil
}

// Check validates the locally-stored token without making a network call.
// Returns ErrNotActivated if Activate has never been called on this machine.
// Returns ErrLicenseExpired if the token is past its grace period.
//
// Use this for periodic in-process checks (e.g. before allowing a gated feature).
func (s *SDK) Check() (*License, error) {
	raw, chain, err := s.store.LoadToken()
	if err != nil {
		return nil, ErrNotActivated
	}

	lic, err := verify.VerifyActivation(s.pubKey, raw, chain)
	if err != nil {
		if errors.Is(err, ports.ErrLicenseInactiveOrExpired) {
			return nil, ErrLicenseExpired
		}
		return nil, ErrNotActivated
	}
	err = validate.Validate(lic, s.machineID)
	if err != nil {
		return nil, ErrNotActivated
	}

	if s.shouldTryRenew(lic) {
		go s.silentRenew(lic)
	}

	if !lic.IsValid() {
		return nil, ErrNotActivated
	}

	return domainToPublic(lic), nil
}

func (s *SDK) shouldTryRenew(lic *domain.License) bool {
	s.renewMu.Lock()
	defer s.renewMu.Unlock()

	if lic.LicenseType == licenseTypePerpetualFixed {
		return false
	}

	if s.renewInFlight {
		return false
	}

	now := time.Now()
	if now.Sub(s.lastRenewAttempt) < minRenewalTime {
		return false
	}
	if now.Sub(lic.IssuedAt) < maxRenewalTime {
		return false
	}
	s.renewInFlight = true
	s.lastRenewAttempt = now
	return true
}

// silentRenew calls POST /v1/renew in the background to keep the token fresh.
// Errors are silently ignored — the existing cached token remains valid until
// its grace period elapses.
func (s *SDK) silentRenew(lic *domain.License) {
	s.renewMu.Lock()
	defer func() {
		s.renewMu.Unlock()
		s.renewInFlight = false
	}()

	if lic.ActivationID == "" || lic.Key == "" {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	now := time.Now()

	if now.Sub(s.lastRenewAttempt) < minRenewalTime {
		return // rate limit
	}

	raw, chain, err := s.renewer.Renew(ctx, lic.ActivationID, lic.Key, s.machineID)
	if err != nil {
		var licenseError *ports.InvalidLicenseError
		// Check if errors is of type invalid license error
		if errors.As(err, &licenseError) {
			// If invalid, delete it from the store
			_ = s.store.SaveToken("", nil)
		}
		return
	}

	if _, err := verify.VerifyActivation(s.pubKey, raw, chain); err != nil {
		return
	}

	if err := validate.Validate(lic, s.machineID); err != nil {
		return
	}

	_ = s.store.SaveToken(raw, chain)
}

// validateLicenseKey is a minimal local sanity check, not a format check:
// a license key may be native or a legacy-system alias (see the
// legacy-key-migration feature in license-latte-api,
// internal/usecase/api/activate_license.go), and only the server knows
// which. It exists only to reject obviously-not-a-key input (empty, or
// implausibly long) without a network round trip.
func (s *SDK) validateLicenseKey(normalized string) error {
	if len(normalized) == 0 || len(normalized) > 256 {
		return ErrInvalidKey
	}
	return nil
}
