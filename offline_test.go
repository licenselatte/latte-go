package latte

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/licenselatte/latte-go/internal/core/domain"
	latthttp "github.com/licenselatte/latte-go/internal/infra/http"
	"github.com/licenselatte/latte-go/internal/infra/storage"
)

// The worked example in license-latte-api/docs/offline-activation.md: the
// server pins the same payload bytes to the same checksum.
func TestOfflineRequestEncodingMatchesTheSpecExample(t *testing.T) {
	file, err := encodeOfflineRequest(offlinePayload{
		ProjectKey: "pk_test_x",
		LicenseKey: "K",
		MachineID:  strings.Repeat("a", 64),
		SDK:        latthttp.SDKInfo{Language: "go", Version: "1.6.0"},
		Nonce:      "000102030405060708090a0b0c0d0e0f",
		CreatedAt:  "2026-11-15T10:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		SHA256 string `json:"sha256"`
	}
	if err := json.Unmarshal(file, &env); err != nil {
		t.Fatal(err)
	}
	if env.SHA256 != "313a6000630e1515af26a405128f76809192996ba4e7f58ca5bb1d95202d0b5a" {
		t.Fatalf("sha256 = %s, want the spec's example", env.SHA256)
	}
}

func offlineSDK(t *testing.T, issuer *lapsedIssuer) *SDK {
	t.Helper()
	return &SDK{
		appID:       "pk_test_APPKEY",
		renewer:     &spyRenewer{},
		store:       storage.NewMemoryStorage(),
		machineID:   lapsedMachine,
		machineName: "render-07",
		masterPubs:  []ed25519.PublicKey{issuer.masterPub},
		now:         func() time.Time { return lapsedNow },
	}
}

func responseFile(t *testing.T, raw string, chain *domain.CertChain, mutate func(map[string]any)) []byte {
	t.Helper()
	f := map[string]any{
		"format": "licenselatte-offline-response", "version": 1, "nonce": "000102030405060708090a0b0c0d0e0f",
		"activation_id": "act-1", "token": raw, "chain": chain,
	}
	if mutate != nil {
		mutate(f)
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestOfflineActivationRequest(t *testing.T) {
	s := offlineSDK(t, newLapsedIssuer(t))

	file, err := s.OfflineActivationRequest("abcd-efgh 1234")
	if err != nil {
		t.Fatalf("OfflineActivationRequest: %v", err)
	}
	var env struct {
		Format  string `json:"format"`
		Version int    `json:"version"`
		Payload string `json:"payload"`
		SHA256  string `json:"sha256"`
	}
	if err := json.Unmarshal(file, &env); err != nil {
		t.Fatal(err)
	}
	body, err := base64.RawURLEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	if env.Format != "licenselatte-offline-request" || env.Version != 1 || env.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("envelope = %+v", env)
	}
	var p offlinePayload
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatal(err)
	}
	if p.ProjectKey != "pk_test_APPKEY" || p.LicenseKey != "ABCDEFGH1234" || p.MachineID != lapsedMachine ||
		p.MachineName != "render-07" || p.SDK.Language != "go" || p.SDK.Version != sdkVersion {
		t.Fatalf("payload = %+v", p)
	}
	if created, err := time.Parse(time.RFC3339, p.CreatedAt); err != nil || !created.Equal(lapsedNow) {
		t.Fatalf("created_at = %q", p.CreatedAt)
	}
	if b, err := hex.DecodeString(p.Nonce); err != nil || len(b) != 16 || strings.ToLower(p.Nonce) != p.Nonce {
		t.Fatalf("nonce = %q", p.Nonce)
	}

	again, _ := s.OfflineActivationRequest("abcd-efgh 1234")
	if string(again) == string(file) {
		t.Fatal("two requests share a nonce")
	}
	if _, err := s.OfflineActivationRequest(""); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("empty key: err = %v, want ErrInvalidKey", err)
	}
}

func TestImportOfflineActivationThenCheckWorksOffline(t *testing.T) {
	issuer := newLapsedIssuer(t)
	s := offlineSDK(t, issuer)
	raw, chain := issuer.token(lapsedNow.Add(-time.Minute), lapsedNow.AddDate(0, 3, 0), lapsedMachine)

	lic, err := s.ImportOfflineActivation(responseFile(t, raw, chain, nil))
	if err != nil {
		t.Fatalf("ImportOfflineActivation: %v", err)
	}
	if lic.Key != "KEY1" || lic.ActivationID != "act-1" {
		t.Fatalf("licence = %+v", lic)
	}
	checked, err := s.Check()
	if err != nil || checked.ActivationID != "act-1" {
		t.Fatalf("Check after import = %+v, %v", checked, err)
	}
}

func TestImportOfflineActivationRefusals(t *testing.T) {
	issuer := newLapsedIssuer(t)
	raw, chain := issuer.token(lapsedNow.Add(-time.Minute), lapsedNow.AddDate(0, 3, 0), lapsedMachine)
	otherRaw, otherChain := issuer.token(lapsedNow.Add(-time.Minute), lapsedNow.AddDate(0, 3, 0), "another-machine")
	expiredRaw, expiredChain := issuer.token(lapsedNow.Add(-96*time.Hour), lapsedNow.AddDate(0, 3, 0), lapsedMachine)
	foreign := newLapsedIssuer(t)
	foreignRaw, foreignChain := foreign.token(lapsedNow.Add(-time.Minute), lapsedNow.AddDate(0, 3, 0), lapsedMachine)

	parts := strings.Split(raw, ".")
	claims, _ := base64.RawURLEncoding.DecodeString(parts[1])
	forged := strings.Replace(string(claims), `"perpetual"`, `"expiring!"`, 1)
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(forged)) + "." + parts[2]

	cases := map[string]struct {
		file []byte
		want error
	}{
		"tampered token":       {responseFile(t, tampered, chain, nil), ErrInvalidOfflineResponse},
		"tampered chain":       {responseFile(t, raw, &domain.CertChain{Submaster: chain.Submaster, Project: otherChain.Project, Daily: chain.Daily}, nil), ErrInvalidOfflineResponse},
		"other root":           {responseFile(t, foreignRaw, foreignChain, nil), ErrInvalidOfflineResponse},
		"other machine":        {responseFile(t, otherRaw, otherChain, nil), ErrInvalidOfflineResponse},
		"past offline window":  {responseFile(t, expiredRaw, expiredChain, nil), ErrLicenseExpired},
		"request file instead": {[]byte(`{"format":"licenselatte-offline-request","version":1}`), ErrInvalidOfflineResponse},
		"unknown version":      {responseFile(t, raw, chain, func(f map[string]any) { f["version"] = 2 }), ErrInvalidOfflineResponse},
		"not json":             {[]byte("not json"), ErrInvalidOfflineResponse},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s := offlineSDK(t, issuer)
			if _, err := s.ImportOfflineActivation(tc.file); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if cached, _, _ := s.store.LoadToken(); cached != "" {
				t.Fatal("a refused response was cached")
			}
		})
	}
}

func TestImportOfflineActivationRefusesAnOlderResponse(t *testing.T) {
	issuer := newLapsedIssuer(t)
	s := offlineSDK(t, issuer)
	oldRaw, oldChain := issuer.token(lapsedNow.Add(-2*time.Hour), lapsedNow.AddDate(0, 3, 0), lapsedMachine)
	newRaw, newChain := issuer.token(lapsedNow.Add(-time.Minute), lapsedNow.AddDate(0, 3, 0), lapsedMachine)

	if _, err := s.ImportOfflineActivation(responseFile(t, newRaw, newChain, nil)); err != nil {
		t.Fatalf("newer: %v", err)
	}
	if _, err := s.ImportOfflineActivation(responseFile(t, oldRaw, oldChain, nil)); !errors.Is(err, ErrStaleOfflineResponse) {
		t.Fatalf("older over newer: err = %v, want ErrStaleOfflineResponse", err)
	}
	if cached, _, _ := s.store.LoadToken(); cached != newRaw {
		t.Fatal("an older response replaced the newer licence")
	}
	// The same file again is not older, so a repeated import succeeds.
	if _, err := s.ImportOfflineActivation(responseFile(t, newRaw, newChain, nil)); err != nil {
		t.Fatalf("same response again: %v", err)
	}
}
