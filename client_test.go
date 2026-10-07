package latte

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientSendsSDKInfo(t *testing.T) {
	got := map[string]map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			SDK map[string]string `json:"sdk"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		got[r.URL.Path] = body.SDK
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := newClient(srv.URL, "pk_test_X")
	_, _, _ = c.Activate(context.Background(), "KEY", "machine")
	_, _, _ = c.Renew(context.Background(), "act", "KEY", "machine")

	for _, path := range []string{"/v1/activate", "/v1/renew"} {
		sdk := got[path]
		if sdk["language"] != "go" || sdk["version"] != sdkVersion {
			t.Errorf("%s: sdk = %v, want language go, version %s", path, sdk, sdkVersion)
		}
	}
}
