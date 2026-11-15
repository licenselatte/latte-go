package latte

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/licenselatte/latte-go/internal/core/domain"
	"github.com/licenselatte/latte-go/internal/core/ports"
	"github.com/licenselatte/latte-go/internal/infra/crypto"
	latthttp "github.com/licenselatte/latte-go/internal/infra/http"
	"github.com/licenselatte/latte-go/internal/infra/validate"
	"github.com/licenselatte/latte-go/internal/infra/verify"
)

// The offline activation file formats, version 1. The contract is
// license-latte-api/docs/offline-activation.md and is shared by every SDK.
const (
	offlineRequestFormat  = "licenselatte-offline-request"
	offlineResponseFormat = "licenselatte-offline-response"
	offlineFormatVersion  = 1
)

var (
	// ErrInvalidOfflineResponse is returned by ImportOfflineActivation for a
	// file that is not a response file, is a version this SDK does not know,
	// does not verify against LicenseLatte's root keys, or was issued for a
	// different machine. The cached licence is left as it was.
	ErrInvalidOfflineResponse = errors.New("licenselatte: invalid offline activation response")

	// ErrStaleOfflineResponse is returned by ImportOfflineActivation when the
	// licence already on this machine was issued after the one in the file.
	ErrStaleOfflineResponse = errors.New("licenselatte: offline activation response is older than the current licence")
)

type offlinePayload struct {
	ProjectKey  string           `json:"project_key"`
	LicenseKey  string           `json:"license_key"`
	MachineID   string           `json:"machine_id"`
	MachineName string           `json:"machine_name,omitempty"`
	SDK         latthttp.SDKInfo `json:"sdk"`
	Nonce       string           `json:"nonce"`
	CreatedAt   string           `json:"created_at"`
}

// encodeOfflineRequest wraps payload in the request file envelope. The
// checksum is over the exact payload bytes, which is why they travel base64
// encoded rather than as a nested object.
func encodeOfflineRequest(payload offlinePayload) ([]byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	return json.MarshalIndent(struct {
		Format  string `json:"format"`
		Version int    `json:"version"`
		Payload string `json:"payload"`
		SHA256  string `json:"sha256"`
	}{offlineRequestFormat, offlineFormatVersion, base64.RawURLEncoding.EncodeToString(body), hex.EncodeToString(sum[:])}, "", "  ")
}

// OfflineActivationRequest returns an activation request file for this
// machine, for a machine that cannot reach the internet. It makes no network
// call. Save the bytes to a file the customer carries to a machine that is
// online, where they upload it on the seller's customer page
// (https://portal.licenselatte.com/<first six characters of the key>/offline)
// and download a response file to bring back to ImportOfflineActivation.
//
// The file holds the licence key, so it should be handled like the key. It is
// accepted for 30 days after it is created.
func (s *SDK) OfflineActivationRequest(licenseKey string) ([]byte, error) {
	normalized := crypto.NormalizeKey(licenseKey)
	if err := s.validateLicenseKey(normalized); err != nil {
		return nil, err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("licenselatte: offline request nonce: %w", err)
	}
	return encodeOfflineRequest(offlinePayload{
		ProjectKey:  s.appID,
		LicenseKey:  normalized,
		MachineID:   s.machineID,
		MachineName: s.machineName,
		SDK:         latthttp.SDKInfo{Language: sdkLanguage, Version: sdkVersion},
		Nonce:       hex.EncodeToString(nonce),
		CreatedAt:   s.clock().UTC().Format(time.RFC3339),
	})
}

// ImportOfflineActivation verifies a response file produced from this
// machine's OfflineActivationRequest and caches the licence it carries, after
// which Activate and Check work offline exactly as after an online
// activation. It makes no network call.
//
// The licence works offline until its grace period ends; to extend it, create
// and exchange a new request before then. A response for another machine, one
// that does not verify, or one older than the licence already cached is
// refused and the cache is left alone.
func (s *SDK) ImportOfflineActivation(response []byte) (*License, error) {
	var file struct {
		Format  string           `json:"format"`
		Version int              `json:"version"`
		Token   string           `json:"token"`
		Chain   domain.CertChain `json:"chain"`
	}
	if err := json.Unmarshal(response, &file); err != nil || file.Format != offlineResponseFormat {
		return nil, fmt.Errorf("%w: not a response file", ErrInvalidOfflineResponse)
	}
	if file.Version != offlineFormatVersion {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrInvalidOfflineResponse, file.Version)
	}

	now := s.clock()
	lic, err := verify.VerifyActivationAnyAt(s.masterPubs, file.Token, &file.Chain, now)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidOfflineResponse, err)
	}
	if err := validate.ValidateAt(lic, s.machineID, now); err != nil {
		if errors.Is(err, ports.ErrGracePeriodExpired) || errors.Is(err, ports.ErrLicenseInactiveOrExpired) || errors.Is(err, ports.ErrLicenseTooOld) {
			return nil, ErrLicenseExpired
		}
		return nil, fmt.Errorf("%w: %w", ErrInvalidOfflineResponse, err)
	}

	// Held so a background renewal cannot write between the comparison and
	// the save.
	s.renewMu.Lock()
	defer s.renewMu.Unlock()
	if raw, chain, err := s.store.LoadToken(); err == nil && raw != "" {
		if cached, err := verify.VerifyActivationAnyAt(s.masterPubs, raw, chain, now); err == nil &&
			validate.ValidateAt(cached, s.machineID, now) == nil && cached.IssuedAt.After(lic.IssuedAt) {
			return nil, ErrStaleOfflineResponse
		}
	}
	if err := s.store.SaveToken(file.Token, &file.Chain); err != nil {
		return nil, fmt.Errorf("licenselatte: save licence: %w", err)
	}
	return s.toPublic(lic), nil
}
