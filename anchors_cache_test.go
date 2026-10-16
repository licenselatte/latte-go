package latte

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/licenselatte/latte-go/internal/core/domain"
	"github.com/licenselatte/latte-go/internal/infra/storage"
	"github.com/licenselatte/latte-go/internal/infra/validate"
	"github.com/licenselatte/latte-go/internal/infra/verify"
)

func readVectorFile(t *testing.T, name string, v any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read %s: %v (did you forget to populate the submodule?)", name, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
}

func decodeMasterKeys(t *testing.T, hexKeys []string) []ed25519.PublicKey {
	t.Helper()
	keys := make([]ed25519.PublicKey, 0, len(hexKeys))
	for _, h := range hexKeys {
		k, err := hex.DecodeString(h)
		if err != nil {
			t.Fatalf("bad master_public_keys_hex entry %q: %v", h, err)
		}
		keys = append(keys, k)
	}
	return keys
}

// TestAnchors runs testdata/anchors.json: a chain whose submaster cert any
// one of the trusted roots signed verifies, one signed outside the list
// does not.
func TestAnchors(t *testing.T) {
	var file struct {
		Cases []struct {
			Name                string    `json:"name"`
			Now                 time.Time `json:"now"`
			MasterPublicKeysHex []string  `json:"master_public_keys_hex"`
			MachineID           string    `json:"machine_id"`
			Token               string    `json:"token"`
			Chain               struct {
				Submaster string `json:"submaster"`
				Project   string `json:"project"`
				Daily     string `json:"daily"`
			} `json:"chain"`
			Expect      string `json:"expect"`
			ExpectStage string `json:"expect_stage"`
		} `json:"cases"`
	}
	readVectorFile(t, "anchors.json", &file)
	if len(file.Cases) == 0 {
		t.Fatal("no cases in anchors.json")
	}
	for _, c := range file.Cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			chain := &domain.CertChain{Submaster: c.Chain.Submaster, Project: c.Chain.Project, Daily: c.Chain.Daily}
			lic, err := verify.VerifyActivationAnyAt(decodeMasterKeys(t, c.MasterPublicKeysHex), c.Token, chain, c.Now)
			if err != nil {
				if c.Expect != "reject" || c.ExpectStage != "verify" {
					t.Fatalf("verify rejected (%v), want %s at %s", err, c.Expect, c.ExpectStage)
				}
				return
			}
			if c.Expect == "reject" && c.ExpectStage == "verify" {
				t.Fatal("verify accepted, want reject at verify")
			}
			if err := validate.ValidateAt(lic, c.MachineID, c.Now); err != nil {
				if c.Expect != "reject" || c.ExpectStage != "validate" {
					t.Fatalf("validate rejected (%v), want %s at %s", err, c.Expect, c.ExpectStage)
				}
				return
			}
			if c.Expect != "accept" {
				t.Fatalf("accepted, want %s at %s", c.Expect, c.ExpectStage)
			}
		})
	}
}

// TestCacheFiles runs testdata/cache_files.json: every unusable cache file
// must come out as not activated, never as a panic.
func TestCacheFiles(t *testing.T) {
	var file struct {
		Now                 time.Time `json:"now"`
		MasterPublicKeysHex []string  `json:"master_public_keys_hex"`
		Cases               []struct {
			Name     string `json:"name"`
			Contents string `json:"contents"`
		} `json:"cases"`
	}
	readVectorFile(t, "cache_files.json", &file)
	if len(file.Cases) == 0 {
		t.Fatal("no cases in cache_files.json")
	}
	keys := decodeMasterKeys(t, file.MasterPublicKeysHex)
	for _, c := range file.Cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s: panic: %v", c.Name, r)
				}
			}()
			path := filepath.Join(t.TempDir(), "cache.latte")
			if err := os.WriteFile(path, []byte(c.Contents), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			token, chain, err := storage.NewFileStorage(path).LoadToken()
			if err != nil {
				return
			}
			if _, err := verify.VerifyActivationAnyAt(keys, token, chain, file.Now); err == nil {
				t.Fatalf("%s: cache file verified, want not activated", c.Name)
			}
		})
	}
}
