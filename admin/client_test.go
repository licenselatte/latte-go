package admin

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

type seen struct {
	method, path, rawQuery, auth, ctype string
	body                                string
}

// fake serves one canned answer and records the request it got.
func fake(t *testing.T, status int, resp string) (*Client, *seen) {
	t.Helper()
	got := &seen{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		*got = seen{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization"), r.Header.Get("Content-Type"), string(b)}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(resp))
	}))
	t.Cleanup(srv.Close)
	c, err := New("llk_test_secret", WithBaseURL(srv.URL+"/v1/"))
	if err != nil {
		t.Fatal(err)
	}
	return c, got
}

func expect(t *testing.T, got *seen, method, path string) {
	t.Helper()
	if got.method != method || got.path != path {
		t.Errorf("request = %s %s, want %s %s", got.method, got.path, method, path)
	}
	if got.auth != "Bearer llk_test_secret" {
		t.Errorf("Authorization = %q", got.auth)
	}
}

const licJSON = `{"id":"i","project_id":"p","policy_id":"pol","license_key":"AB-CD","status":"suspended",
"expires_at":null,"metadata":{"a":1},"client_metadata":{},"created_at":"2026-01-01T00:00:00Z",
"updated_at":"2026-01-02T00:00:00Z","future_field":{"x":true}}`

func TestNewRequiresKey(t *testing.T) {
	if _, err := New(""); !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("err = %v", err)
	}
}

func TestTimeoutAndHTTPClientOverride(t *testing.T) {
	base := &http.Client{}
	c, _ := New("k", WithHTTPClient(base), WithTimeout(time.Second))
	if c.http.Timeout != time.Second || base.Timeout != 0 {
		t.Errorf("timeout = %v, caller's client = %v", c.http.Timeout, base.Timeout)
	}
	if c.baseURL != DefaultBaseURL {
		t.Errorf("baseURL = %q", c.baseURL)
	}
}

func TestIssueLicense(t *testing.T) {
	c, got := fake(t, 201, licJSON)
	l, err := c.IssueLicense(context.Background(), IssueLicenseParams{
		PolicyID: "pol", CustomerEmail: "b@example.com", Metadata: map[string]any{"order": "1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, got, "POST", "/v1/licenses")
	if got.ctype != "application/json" {
		t.Errorf("content-type = %q", got.ctype)
	}
	if got.body != `{"policy_id":"pol","customer_email":"b@example.com","metadata":{"order":"1"}}` {
		t.Errorf("body = %s", got.body)
	}
	if l.LicenseKey != "AB-CD" || l.Status != StatusSuspended || l.ExpiresAt != nil || l.CreatedAt.Year() != 2026 {
		t.Errorf("license = %+v", l)
	}
	if string(l.Raw["future_field"]) != `{"x":true}` {
		t.Errorf("raw future_field = %s", l.Raw["future_field"])
	}
}

func TestListLicensesQuery(t *testing.T) {
	c, got := fake(t, 200, `{"licenses":[`+licJSON+`],"total":7}`)
	out, err := c.ListLicenses(context.Background(), ListLicensesParams{
		Limit: 10, Offset: 20, CustomerEmail: "a+b@example.com", Status: StatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, got, "GET", "/v1/licenses")
	if got.rawQuery != "customer_email=a%2Bb%40example.com&limit=10&offset=20&status=active" {
		t.Errorf("query = %s", got.rawQuery)
	}
	if out.Total != 7 || len(out.Licenses) != 1 {
		t.Errorf("out = %+v", out)
	}
	if _, err := c.ListLicenses(context.Background(), ListLicensesParams{}); err != nil || got.rawQuery != "" {
		t.Errorf("empty params: err=%v query=%q", err, got.rawQuery)
	}
}

func TestGetLicenseEscapesKey(t *testing.T) {
	c, got := fake(t, 200, licJSON)
	if _, err := c.GetLicense(context.Background(), "AB/CD EF"); err != nil {
		t.Fatal(err)
	}
	expect(t, got, "GET", "/v1/licenses/AB/CD EF")
}

func TestUpdateLicenseBodies(t *testing.T) {
	exp := time.Date(2027, 1, 2, 3, 4, 5, 0, time.FixedZone("x", 3600))
	cases := []struct {
		name string
		p    UpdateLicenseParams
		want string
	}{
		{"nothing", UpdateLicenseParams{}, `{}`},
		{"replace maps", UpdateLicenseParams{Metadata: map[string]any{"a": 1}, ClientMetadata: map[string]any{}}, `{"client_metadata":{},"metadata":{"a":1}}`},
		{"expiry", UpdateLicenseParams{ExpiresAt: &exp}, `{"expires_at":"2027-01-02T02:04:05Z"}`},
		{"clear expiry", UpdateLicenseParams{ClearExpiresAt: true, ExpiresAt: &exp}, `{"expires_at":null}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, got := fake(t, 200, licJSON)
			if _, err := c.UpdateLicense(context.Background(), "K", tc.p); err != nil {
				t.Fatal(err)
			}
			expect(t, got, "PATCH", "/v1/licenses/K")
			if got.body != tc.want {
				t.Errorf("body = %s, want %s", got.body, tc.want)
			}
		})
	}
}

func TestRevokeAndReleaseAre204(t *testing.T) {
	c, got := fake(t, 204, ``)
	if err := c.RevokeLicense(context.Background(), "K"); err != nil {
		t.Fatal(err)
	}
	expect(t, got, "DELETE", "/v1/licenses/K")
	if err := c.ReleaseActivation(context.Background(), "K", "act-1"); err != nil {
		t.Fatal(err)
	}
	expect(t, got, "DELETE", "/v1/licenses/K/activations/act-1")
	if got.body != "" || got.ctype != "" {
		t.Errorf("bodiless request sent body %q / %q", got.body, got.ctype)
	}
}

func TestSuspendReinstate(t *testing.T) {
	c, got := fake(t, 200, licJSON)
	if l, err := c.SuspendLicense(context.Background(), "K"); err != nil || l.ID != "i" {
		t.Fatalf("suspend: %v %v", l, err)
	}
	expect(t, got, "POST", "/v1/licenses/K/suspend")
	if _, err := c.ReinstateLicense(context.Background(), "K"); err != nil {
		t.Fatal(err)
	}
	expect(t, got, "POST", "/v1/licenses/K/reinstate")
}

func TestResend202(t *testing.T) {
	c, got := fake(t, 202, `{"status":"queued"}`)
	if err := c.ResendLicenseEmail(context.Background(), "K"); err != nil {
		t.Fatal(err)
	}
	expect(t, got, "POST", "/v1/licenses/K/resend")
}

func TestListActivations(t *testing.T) {
	c, got := fake(t, 200, `{"activations":[{"id":"a1","status":"active","machine_id_hash":"h",
"activated_at":"2026-01-01T00:00:00Z","last_renewed_at":null,"deactivated_at":null,"seat_held_until":null,
"sdk":{"language":"go"},"metadata":{"name":"mac"},"extra":1}]}`)
	acts, err := c.ListActivations(context.Background(), "K")
	if err != nil {
		t.Fatal(err)
	}
	expect(t, got, "GET", "/v1/licenses/K/activations")
	a := acts[0]
	if a.ID != "a1" || a.ActivatedAt == nil || a.LastRenewedAt != nil || !reflect.DeepEqual(a.Metadata, map[string]any{"name": "mac"}) {
		t.Errorf("activation = %+v", a)
	}
	if string(a.Raw["extra"]) != "1" {
		t.Errorf("raw extra = %s", a.Raw["extra"])
	}
}

func TestListPolicies(t *testing.T) {
	c, got := fake(t, 200, `{"policies":[{"id":"p1","name":"Pro","license_type":"expiring","expiry_mode":"from_issuance",
"expiry_date":null,"expiry_days":365,"max_activations":null,"grace_period_hours":168,"created_at":"2026-03-04T11:20:41.882Z"}]}`)
	ps, err := c.ListPolicies(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	expect(t, got, "GET", "/v1/policies")
	p := ps[0]
	if p.ID != "p1" || *p.ExpiryDays != 365 || p.MaxActivations != nil || *p.GracePeriodHours != 168 {
		t.Errorf("policy = %+v", p)
	}
}

func TestErrorMapping(t *testing.T) {
	for _, status := range []int{400, 401, 403, 404, 409, 429} {
		c, _ := fake(t, status, `{"error":"nope","code":"plan_license_limit_reached"}`)
		_, err := c.GetLicense(context.Background(), "K")
		var e *Error
		if !errors.As(err, &e) || e.StatusCode != status || e.Message != "nope" || e.Code != "plan_license_limit_reached" {
			t.Errorf("status %d: err = %#v", status, err)
		}
	}
	c, _ := fake(t, 502, `<html>bad gateway</html>`)
	var e *Error
	if err := c.RevokeLicense(context.Background(), "K"); !errors.As(err, &e) || e.Message != "Bad Gateway" {
		t.Errorf("non-JSON error body: %v", err)
	}
}

func TestWritesAreNotRetried(t *testing.T) {
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		w.WriteHeader(429)
	}))
	defer srv.Close()
	c, _ := New("k", WithBaseURL(srv.URL))
	_, _ = c.IssueLicense(context.Background(), IssueLicenseParams{PolicyID: "p"})
	if n != 1 {
		t.Errorf("requests = %d, want 1", n)
	}
}

func TestMalformedSuccessBody(t *testing.T) {
	c, _ := fake(t, 200, `not json`)
	if _, err := c.GetLicense(context.Background(), "K"); err == nil {
		t.Error("want decode error")
	}
}
