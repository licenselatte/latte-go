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
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/denisbrodbeck/machineid"
	"github.com/golang-jwt/jwt/v5"
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

	// MachineID optionally replaces the operating system's machine ID as the
	// identity of this install. When empty, the SDK reads the OS machine ID.
	// Either way the raw value never leaves the machine: the SDK sends
	// lowercase hex HMAC-SHA256(key = raw ID, message = "licenselatte_" + AppID),
	// with a supplied value used byte for byte, without trimming.
	//
	// Set it when the OS machine ID does not identify what you want to count
	// as one seat: containers that share their image's /etc/machine-id or
	// have none, cloned VMs that share one ID, apps that want a seat per user
	// rather than per machine, and tests. Changing it on an install that is
	// already activated makes that install a new machine, which takes a new
	// seat.
	MachineID string

	// MachineName is the name this machine is given when it activates, shown
	// to the customer in Machines and the portal and to you in the dashboard.
	// When empty, the SDK sends the operating system's hostname. A name the
	// customer sets later with RenameMachine is kept on re-activation.
	MachineName string

	// NoMachineName sends no name on activation, hostname included.
	NoMachineName bool
}

// SDK is the main entry point. Create one instance per application.
type SDK struct {
	appID            string
	appKey           string // 32-char portion after "pk_{env}_"
	activator        ports.Activator
	renewer          ports.Renewer
	machines         ports.MachineManager
	store            ports.Storage
	machineID        string
	renewMu          sync.Mutex // serializes a renewal with Deactivate
	stateMu          sync.Mutex // guards lastRenewAttempt, renewInFlight and renewFailed; never held across I/O
	lastRenewAttempt time.Time
	renewInFlight    bool
	renewFailed      bool // the last renewal could not reach the server; in memory only, guarded by stateMu
	masterPubs       []ed25519.PublicKey
	now              func() time.Time // nil means time.Now; tests pin it
}

// newClient returns the API client, identifying this SDK's language and
// version on every request.
func newClient(apiURL, appID, machineName string) interface {
	ports.Activator
	ports.Renewer
	ports.MachineManager
} {
	return latthttp.NewHttpClient(apiURL, appID, latthttp.SDKInfo{Language: sdkLanguage, Version: sdkVersion}, machineName)
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
	case envLive, envTest:
		apiURL = publicURL
	case envLocal:
		apiURL = localURL
	}

	machineName := config.MachineName
	if config.NoMachineName {
		machineName = ""
	} else if machineName == "" {
		// The name is a courtesy, so a hostname the OS will not give is no name.
		machineName, _ = os.Hostname()
	}
	client := newClient(apiURL, config.AppID, machineName)

	storePath, err := resolveStoragePath(appKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStorageInitFailed, err)
	}

	rawMachineID := config.MachineID
	if rawMachineID == "" {
		rawMachineID, err = machineid.ID()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrMachineIDFailed, err)
		}
	}
	machineID := protectMachineID(rawMachineID, config.AppID)

	return &SDK{
		appID:      config.AppID,
		appKey:     appKey,
		activator:  client,
		renewer:    client,
		machines:   client,
		store:      storage.NewFileStorage(storePath),
		machineID:  machineID,
		masterPubs: masterPublicKeys(),
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
		if lic, err := verify.VerifyActivationAnyAt(s.masterPubs, raw, chain, s.clock()); err == nil {
			if err := validate.ValidateAt(lic, s.machineID, s.clock()); err == nil {
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
					return s.toPublic(lic), nil
				}
			}
		}
	}

	// Cache miss or expired: activate via network.
	raw, chain, err := s.activator.Activate(ctx, normalized, s.machineID)
	if err != nil {
		return nil, mapNetworkError(err)
	}

	lic, err := verify.VerifyActivationAnyAt(s.masterPubs, raw, chain, s.clock())
	if err != nil {
		return nil, fmt.Errorf("licenselatte: server returned invalid token: %w", err)
	}

	err = validate.ValidateAt(lic, s.machineID, s.clock())
	if err != nil {
		return nil, fmt.Errorf("licenselatte: server returned invalid token: %w", err)
	}

	_ = s.store.SaveToken(raw, chain)
	s.setRenewFailed(false)

	return s.toPublic(lic), nil
}

// Check validates the locally-stored token without making a network call.
// Returns ErrNotActivated if Activate has never been called on this machine.
// Returns ErrLicenseExpired if the token is past its grace period.
//
// A token that is past its grace period but was genuinely issued for this
// machine is renewed in the background; Check keeps returning an error until
// the renewal has saved a new token, so re-check a few seconds later.
//
// Use this for periodic in-process checks (e.g. before allowing a gated feature).
func (s *SDK) Check() (*License, error) {
	raw, chain, err := s.store.LoadToken()
	if err != nil {
		return nil, ErrNotActivated
	}

	lic, err := verify.VerifyActivationAnyAt(s.masterPubs, raw, chain, s.clock())
	if err != nil {
		s.renewLapsed(raw, chain)
		if errors.Is(err, ports.ErrLicenseInactiveOrExpired) {
			return nil, ErrLicenseExpired
		}
		return nil, ErrNotActivated
	}
	err = validate.ValidateAt(lic, s.machineID, s.clock())
	if err != nil {
		s.renewLapsed(raw, chain)
		return nil, ErrNotActivated
	}

	if s.shouldTryRenew(lic) {
		go s.silentRenew(lic)
	}

	if !lic.IsValid() {
		return nil, ErrNotActivated
	}

	return s.toPublic(lic), nil
}

// renewLapsed starts a background renewal for a cached token that Check
// rejects only because time has passed: its offline window or licence end is
// over, or a cert in its chain has expired. The server accepts a renewal
// whatever the token's age, so a machine that was off for longer than the
// grace window recovers without a new activation. The signature chain and
// machine id must still verify, since the activation id and key sent to the
// server come from the token. Check's own result is not affected.
func (s *SDK) renewLapsed(raw string, chain *domain.CertChain) {
	lic, err := verify.VerifyActivationIgnoringExpiryAnyAt(s.masterPubs, raw, chain, s.clock())
	if err != nil {
		return
	}
	err = validate.ValidateAt(lic, s.machineID, s.clock())
	if err != nil && !errors.Is(err, ports.ErrGracePeriodExpired) &&
		!errors.Is(err, ports.ErrLicenseInactiveOrExpired) && !errors.Is(err, ports.ErrLicenseTooOld) {
		return
	}
	if s.shouldTryRenew(lic) {
		go s.silentRenew(lic)
	}
}

// clock is the current time; tests pin it through now.
func (s *SDK) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *SDK) setRenewFailed(v bool) {
	s.stateMu.Lock()
	s.renewFailed = v
	s.stateMu.Unlock()
}

func (s *SDK) toPublic(lic *domain.License) *License {
	s.stateMu.Lock()
	failed := s.renewFailed
	s.stateMu.Unlock()
	return domainToPublic(lic, s.clock(), failed)
}

func (s *SDK) shouldTryRenew(lic *domain.License) bool {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()

	if s.renewInFlight {
		return false
	}

	now := s.clock()
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
	// renewInFlight is cleared under stateMu after renewMu is released.
	s.renewMu.Lock()
	defer func() {
		s.renewMu.Unlock()
		s.stateMu.Lock()
		s.renewInFlight = false
		s.stateMu.Unlock()
	}()

	if lic.ActivationID == "" || lic.Key == "" {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	raw, chain, err := s.renewer.Renew(ctx, lic.ActivationID, lic.Key, s.machineID)
	// A renewal that outlived its activation reports nothing: the flag
	// belongs to whatever activation the SDK holds now.
	if !s.holdsActivation(lic.ActivationID) {
		return
	}
	if err != nil {
		var licenseError *ports.InvalidLicenseError
		// Check if errors is of type invalid license error
		if errors.As(err, &licenseError) {
			// If invalid, delete it from the store
			_ = s.store.SaveToken("", nil)
		}
		// Only a failure to reach the server counts: any other answer, a
		// rejection or a server error, means the server was reached.
		s.setRenewFailed(errors.Is(err, ports.ErrNetworkError))
		return
	}

	// Whatever happens to the new token, the server answered.
	s.setRenewFailed(false)

	renewed, err := verify.VerifyActivationAnyAt(s.masterPubs, raw, chain, s.clock())
	if err != nil {
		return
	}

	if err := validate.ValidateAt(renewed, s.machineID, s.clock()); err != nil {
		return
	}

	_ = s.store.SaveToken(raw, chain)
}

// holdsActivation reports whether the cached token still belongs to
// activationID. A renewal checks it before touching the cache, under renewMu,
// so one that outlives a Deactivate (and a fresh Activate after it) can
// neither write the released activation back nor wipe the new one.
func (s *SDK) holdsActivation(activationID string) bool {
	cached, _, err := s.cachedCredentials()
	return err == nil && cached == activationID
}

// Deactivate releases this machine's seat so the licence can be activated on
// another machine. It needs the network: the server releases the seat first,
// and only once it has answered does the SDK delete the cached token, after
// which Check returns ErrNotActivated until the next Activate. When the call
// fails, the token is kept and the call can be retried; a machine that is lost
// or dead is released from the seller's customer portal instead.
//
// A release that already happened, on this call or an earlier one, is
// success. When the seller's policy refuses the release, the error is a
// *DeactivationBlockedError, which matches ErrDeactivationBlocked.
func (s *SDK) Deactivate() (*DeactivateResult, error) {
	return s.DeactivateWithContext(context.Background())
}

// DeactivateWithContext is the context-aware version of Deactivate.
func (s *SDK) DeactivateWithContext(ctx context.Context) (*DeactivateResult, error) {
	// Held for the whole call so a background renewal can neither be running
	// nor start until the token is gone; one that runs afterwards finds the
	// activation released and removes nothing but an empty cache.
	s.renewMu.Lock()
	defer s.renewMu.Unlock()

	activationID, key, err := s.cachedCredentials()
	if err != nil {
		return nil, err
	}
	released, seatFreeAt, err := s.machines.Deactivate(ctx, activationID, key, s.machineID)
	if err != nil {
		return nil, mapNetworkError(err)
	}
	_ = s.store.SaveToken("", nil)
	s.setRenewFailed(false)
	return &DeactivateResult{Released: released, SeatFreeAt: seatFreeAt}, nil
}

// Machines lists the machines holding a seat on this machine's licence. It
// needs the network and an active activation on this machine.
func (s *SDK) Machines() ([]Machine, error) {
	return s.MachinesWithContext(context.Background())
}

// MachinesWithContext is the context-aware version of Machines.
func (s *SDK) MachinesWithContext(ctx context.Context) ([]Machine, error) {
	activationID, key, err := s.cachedCredentials()
	if err != nil {
		return nil, err
	}
	machines, err := s.machines.Machines(ctx, activationID, key, s.machineID)
	if err != nil {
		return nil, mapNetworkError(err)
	}
	return machines, nil
}

// RenameMachine names this machine and returns the name as stored, trimmed.
// The server refuses a name that is empty, longer than 64 characters or holds
// control characters.
func (s *SDK) RenameMachine(name string) (string, error) {
	return s.RenameMachineWithContext(context.Background(), name)
}

// RenameMachineWithContext is the context-aware version of RenameMachine.
func (s *SDK) RenameMachineWithContext(ctx context.Context, name string) (string, error) {
	activationID, key, err := s.cachedCredentials()
	if err != nil {
		return "", err
	}
	stored, err := s.machines.RenameMachine(ctx, activationID, key, s.machineID, name)
	if err != nil {
		return "", mapNetworkError(err)
	}
	return stored, nil
}

// cachedCredentials reads the activation id and licence key out of the
// cached token. The token is not verified: the server authenticates these
// calls itself, and a machine whose token has outlived its grace window or
// its certificate chain still holds a seat it must be able to release.
func (s *SDK) cachedCredentials() (activationID, key string, err error) {
	raw, _, err := s.store.LoadToken()
	if err != nil || raw == "" {
		return "", "", ErrNotActivated
	}
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(raw, claims); err != nil {
		return "", "", ErrNotActivated
	}
	activationID, _ = claims["aid"].(string)
	key, _ = claims["sub"].(string)
	if activationID == "" || key == "" {
		return "", "", ErrNotActivated
	}
	return activationID, key, nil
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
