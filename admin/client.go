// Package admin is a server-side client for the LicenseLatte admin REST API:
// issue, inspect, update, suspend, revoke and release licenses from your own
// backend.
//
// An API key is a secret. Use this package only in code you run yourself and
// never in an application you ship to end users; client apps use the parent
// latte package, which needs no secret.
package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultBaseURL is the production API root.
const DefaultBaseURL = "https://api.licenselatte.com/v1"

const defaultTimeout = 30 * time.Second

// ErrMissingAPIKey is returned by New when the API key is empty.
var ErrMissingAPIKey = errors.New("licenselatte/admin: API key is required")

// Error is a non-2xx answer from the API. Branch on StatusCode; Message is
// written for a human reading a log.
type Error struct {
	StatusCode int
	Message    string
	// Code is a machine-readable refusal code when the API sends one, such as
	// "plan_license_limit_reached" on a 409 from IssueLicense.
	Code string
}

func (e *Error) Error() string {
	return fmt.Sprintf("licenselatte/admin: HTTP %d: %s", e.StatusCode, e.Message)
}

// Client calls the admin API with one project-scoped API key. It is safe for
// concurrent use. Writes are never retried.
type Client struct {
	apiKey  string
	baseURL string
	http    *http.Client
}

// Option configures New.
type Option func(*config)

type config struct {
	baseURL string
	http    *http.Client
	timeout time.Duration
}

// WithBaseURL replaces DefaultBaseURL, for example to target a local server.
func WithBaseURL(u string) Option { return func(c *config) { c.baseURL = u } }

// WithHTTPClient replaces the default HTTP client.
func WithHTTPClient(h *http.Client) Option { return func(c *config) { c.http = h } }

// WithTimeout sets the per-request timeout, on top of any context deadline.
// It applies to a copy of the client from WithHTTPClient, if one is given.
func WithTimeout(d time.Duration) Option { return func(c *config) { c.timeout = d } }

// New returns a Client for apiKey (llk_live_... or llk_test_...).
func New(apiKey string, opts ...Option) (*Client, error) {
	if apiKey == "" {
		return nil, ErrMissingAPIKey
	}
	cfg := config{baseURL: DefaultBaseURL, timeout: defaultTimeout}
	for _, o := range opts {
		o(&cfg)
	}
	h := cfg.http
	if h == nil {
		h = &http.Client{}
	}
	if cfg.timeout > 0 {
		cp := *h
		cp.Timeout = cfg.timeout
		h = &cp
	}
	return &Client{apiKey: apiKey, baseURL: strings.TrimRight(cfg.baseURL, "/"), http: h}, nil
}

// do sends one request and decodes a 2xx JSON body into out (nil to discard).
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("licenselatte/admin: encode request: %w", err)
		}
		rdr = bytes.NewReader(b)
	}
	u := c.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return fmt.Errorf("licenselatte/admin: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("licenselatte/admin: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("licenselatte/admin: read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		e := &Error{StatusCode: resp.StatusCode}
		var b struct {
			Error string `json:"error"`
			Code  string `json:"code"`
		}
		_ = json.Unmarshal(data, &b)
		e.Message, e.Code = b.Error, b.Code
		if e.Message == "" {
			e.Message = http.StatusText(resp.StatusCode)
		}
		return e
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("licenselatte/admin: decode response: %w", err)
	}
	return nil
}

func licensePath(key string, rest ...string) string {
	p := "/licenses/" + url.PathEscape(key)
	for _, r := range rest {
		p += "/" + url.PathEscape(r)
	}
	return p
}

// IssueLicense creates a license under the policy named by p.PolicyID.
func (c *Client) IssueLicense(ctx context.Context, p IssueLicenseParams) (*License, error) {
	var l License
	if err := c.do(ctx, http.MethodPost, "/licenses", nil, p, &l); err != nil {
		return nil, err
	}
	return &l, nil
}

// ListLicenses returns one page of licenses. A zero Limit returns every
// license in the project.
func (c *Client) ListLicenses(ctx context.Context, p ListLicensesParams) (*LicenseList, error) {
	q := url.Values{}
	if p.Limit > 0 {
		q.Set("limit", strconv.Itoa(p.Limit))
	}
	if p.Offset > 0 {
		q.Set("offset", strconv.Itoa(p.Offset))
	}
	if p.CustomerEmail != "" {
		q.Set("customer_email", p.CustomerEmail)
	}
	if p.Status != "" {
		q.Set("status", string(p.Status))
	}
	var out LicenseList
	if err := c.do(ctx, http.MethodGet, "/licenses", q, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetLicense fetches one license by key.
func (c *Client) GetLicense(ctx context.Context, licenseKey string) (*License, error) {
	var l License
	if err := c.do(ctx, http.MethodGet, licensePath(licenseKey), nil, nil, &l); err != nil {
		return nil, err
	}
	return &l, nil
}

// UpdateLicense changes the fields set in p and leaves the rest alone.
func (c *Client) UpdateLicense(ctx context.Context, licenseKey string, p UpdateLicenseParams) (*License, error) {
	var l License
	if err := c.do(ctx, http.MethodPatch, licensePath(licenseKey), nil, p, &l); err != nil {
		return nil, err
	}
	return &l, nil
}

// RevokeLicense permanently refuses the license.
func (c *Client) RevokeLicense(ctx context.Context, licenseKey string) error {
	return c.do(ctx, http.MethodDelete, licensePath(licenseKey), nil, nil, nil)
}

// SuspendLicense refuses the license until ReinstateLicense.
func (c *Client) SuspendLicense(ctx context.Context, licenseKey string) (*License, error) {
	var l License
	if err := c.do(ctx, http.MethodPost, licensePath(licenseKey, "suspend"), nil, nil, &l); err != nil {
		return nil, err
	}
	return &l, nil
}

// ReinstateLicense lifts a suspension.
func (c *Client) ReinstateLicense(ctx context.Context, licenseKey string) (*License, error) {
	var l License
	if err := c.do(ctx, http.MethodPost, licensePath(licenseKey, "reinstate"), nil, nil, &l); err != nil {
		return nil, err
	}
	return &l, nil
}

// ListActivations returns the machines that hold or held a seat on the license.
func (c *Client) ListActivations(ctx context.Context, licenseKey string) ([]Activation, error) {
	var out struct {
		Activations []Activation `json:"activations"`
	}
	if err := c.do(ctx, http.MethodGet, licensePath(licenseKey, "activations"), nil, nil, &out); err != nil {
		return nil, err
	}
	return out.Activations, nil
}

// ReleaseActivation frees one machine's seat.
func (c *Client) ReleaseActivation(ctx context.Context, licenseKey, activationID string) error {
	return c.do(ctx, http.MethodDelete, licensePath(licenseKey, "activations", activationID), nil, nil, nil)
}

// ResendLicenseEmail queues the license-key email to the buyer again.
func (c *Client) ResendLicenseEmail(ctx context.Context, licenseKey string) error {
	return c.do(ctx, http.MethodPost, licensePath(licenseKey, "resend"), nil, nil, nil)
}

// ListPolicies returns the project's policies, to resolve a policy id for IssueLicense.
func (c *Client) ListPolicies(ctx context.Context) ([]Policy, error) {
	var out struct {
		Policies []Policy `json:"policies"`
	}
	if err := c.do(ctx, http.MethodGet, "/policies", nil, nil, &out); err != nil {
		return nil, err
	}
	return out.Policies, nil
}
