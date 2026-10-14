package latte

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/licenselatte/latte-go/internal/core/domain"
	"github.com/licenselatte/latte-go/internal/infra/storage"
)

// machinesSDK is an SDK pointed at srv whose cache holds a token naming
// activation "act-1" for key "KEY1". The token is not a valid licence: the
// machine calls read its claims without verifying them.
func machinesSDK(t *testing.T, srv *httptest.Server) (*SDK, *storage.FileStorage) {
	t.Helper()
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"aid": "act-1", "sub": "KEY1"}).SignedString([]byte("k"))
	if err != nil {
		t.Fatal(err)
	}
	store := storage.NewFileStorage(filepath.Join(t.TempDir(), "cache.latte"))
	if err := store.SaveToken(token, &domain.CertChain{Submaster: "s", Project: "p", Daily: "d"}); err != nil {
		t.Fatal(err)
	}
	client := newClient(srv.URL, "pk_test_X", "")
	return &SDK{activator: client, renewer: client, machines: client, store: store, machineID: "machine-hash"}, store
}

func cached(t *testing.T, store *storage.FileStorage) string {
	t.Helper()
	raw, _, _ := store.LoadToken()
	return raw
}

func TestDeactivate(t *testing.T) {
	var path string
	var body map[string]any
	status, answer := http.StatusOK, `{"released":true,"seat_free_at":"2026-10-21T09:00:00Z"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(answer))
	}))
	defer srv.Close()

	t.Run("sends renew's credentials and forgets the token", func(t *testing.T) {
		sdk, store := machinesSDK(t, srv)
		res, err := sdk.Deactivate()
		if err != nil {
			t.Fatal(err)
		}
		if path != "/v1/deactivate" || body["activation_id"] != "act-1" || body["license_key"] != "KEY1" || body["machine_id"] != "machine-hash" || body["sdk"] == nil {
			t.Errorf("request: %s %v", path, body)
		}
		if !res.Released || res.SeatFreeAt == nil || !res.SeatFreeAt.Equal(time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)) {
			t.Errorf("result: %+v", res)
		}
		if cached(t, store) != "" {
			t.Error("the token survived a release")
		}
		if _, err := sdk.Check(); !errors.Is(err, ErrNotActivated) {
			t.Errorf("Check after release: %v", err)
		}
		if _, err := sdk.Deactivate(); !errors.Is(err, ErrNotActivated) {
			t.Errorf("Deactivate with nothing cached: %v", err)
		}
	})

	t.Run("an earlier release is success too", func(t *testing.T) {
		status, answer = http.StatusOK, `{"released":false,"seat_free_at":null}`
		sdk, store := machinesSDK(t, srv)
		if res, err := sdk.Deactivate(); err != nil || res.Released {
			t.Fatalf("got %+v, %v", res, err)
		}
		if cached(t, store) != "" {
			t.Error("the token survived a release")
		}
	})

	t.Run("a policy refusal keeps the token", func(t *testing.T) {
		status, answer = http.StatusConflict, `{"error":"Wait a week.","reason":"deactivation_cooldown","available_at":"2026-10-21T09:00:00Z"}`
		sdk, store := machinesSDK(t, srv)
		_, err := sdk.Deactivate()
		var blocked *DeactivationBlockedError
		if !errors.Is(err, ErrDeactivationBlocked) || !errors.As(err, &blocked) {
			t.Fatalf("want DeactivationBlockedError, got %v", err)
		}
		if blocked.Reason != "deactivation_cooldown" || blocked.Message != "Wait a week." || blocked.AvailableAt == nil {
			t.Errorf("blocked: %+v", blocked)
		}
		if cached(t, store) == "" {
			t.Error("a refused release deleted the token")
		}
	})

	t.Run("an inactive licence keeps the token, unlike renew", func(t *testing.T) {
		status, answer = http.StatusForbidden, `{"error":"license is inactive or expired","reason":"license_suspended"}`
		sdk, store := machinesSDK(t, srv)
		if _, err := sdk.Deactivate(); !errors.Is(err, ErrLicenseExpired) {
			t.Fatalf("want ErrLicenseExpired, got %v", err)
		}
		if cached(t, store) == "" {
			t.Error("a refused release deleted the token")
		}
	})

	t.Run("a network failure keeps the token", func(t *testing.T) {
		dead := httptest.NewServer(http.NotFoundHandler())
		dead.Close()
		sdk, store := machinesSDK(t, dead)
		if _, err := sdk.Deactivate(); err == nil {
			t.Fatal("want an error")
		}
		if cached(t, store) == "" {
			t.Error("a failed release deleted the token")
		}
	})
}

func TestMachinesAndRename(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch r.URL.Path {
		case "/v1/machines":
			_, _ = w.Write([]byte(`{"machines":[
				{"machine_name":"Studio","machine_fingerprint":"9f1c4a0b2d3e","activated_at":"2026-10-01T00:00:00Z","last_seen_at":"2026-10-14T00:00:00Z","current":true},
				{"machine_fingerprint":"0a1b2c3d4e5f","activated_at":"2026-09-01T00:00:00Z","last_seen_at":"2026-09-02T00:00:00Z","seat_free_at":"2026-10-20T00:00:00Z","current":false}]}`))
		case "/v1/machines/rename":
			_, _ = w.Write([]byte(`{"machine_name":"Studio Mac"}`))
		}
	}))
	defer srv.Close()
	sdk, _ := machinesSDK(t, srv)

	machines, err := sdk.Machines()
	if err != nil {
		t.Fatal(err)
	}
	if len(machines) != 2 || machines[0].Name != "Studio" || !machines[0].Current || machines[0].SeatFreeAt != nil ||
		machines[1].Name != "" || machines[1].SeatFreeAt == nil {
		t.Errorf("machines: %+v", machines)
	}

	name, err := sdk.RenameMachine(" Studio Mac ")
	if err != nil || name != "Studio Mac" || body["machine_name"] != " Studio Mac " || body["activation_id"] != "act-1" {
		t.Errorf("rename: %q, %v, body %v", name, err, body)
	}
}

func TestActivateSendsMachineName(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body = nil
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	for name, want := range map[string]any{"Studio Mac": "Studio Mac", "": nil} {
		_, _, _ = newClient(srv.URL, "pk_test_X", name).Activate(context.Background(), "KEY", "machine")
		if body["machine_name"] != want {
			t.Errorf("name %q: sent %v", name, body["machine_name"])
		}
	}
}
