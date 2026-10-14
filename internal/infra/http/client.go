package http

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/licenselatte/latte-go/internal/core/domain"
	"github.com/licenselatte/latte-go/internal/core/ports"
)

type httpClient struct {
	endpoint    string
	projectKey  string
	sdk         SDKInfo
	machineName string
	http        *http.Client
}

// SDKInfo identifies this SDK to the API, sent as "sdk" in every request body.
type SDKInfo struct {
	Language string `json:"language"`
	Version  string `json:"version"`
}

// NewHttpClient returns an Activator, Renewer and MachineManager backed by the
// LicenseLatte HTTP API. machineName is sent on activation; empty sends none.
func NewHttpClient(endpoint string, projectKey string, sdk SDKInfo, machineName string) interface {
	ports.Activator
	ports.Renewer
	ports.MachineManager
} {
	return &httpClient{
		endpoint:    endpoint,
		projectKey:  projectKey,
		sdk:         sdk,
		machineName: machineName,
		http:        &http.Client{},
	}
}

// --- Activate ---

type activateRequest struct {
	ProjectKey    string  `json:"project_key"`
	LicenseKey    string  `json:"license_key"`
	MachineIDHash string  `json:"machine_id"`
	MachineName   string  `json:"machine_name,omitempty"`
	SDK           SDKInfo `json:"sdk"`
}

func (c *httpClient) Activate(ctx context.Context, licenseKey, machineID string) (string, *domain.CertChain, error) {
	body, _ := json.Marshal(activateRequest{
		ProjectKey:    c.projectKey,
		LicenseKey:    licenseKey,
		MachineIDHash: machineID,
		MachineName:   c.machineName,
		SDK:           c.sdk,
	})

	return c.post(ctx, "/v1/activate", body)
}

// --- Renew ---

type renewRequest struct {
	ActivationID  string  `json:"activation_id"`
	LicenseKey    string  `json:"license_key"`
	MachineIDHash string  `json:"machine_id"`
	SDK           SDKInfo `json:"sdk"`
}

func (c *httpClient) Renew(ctx context.Context, activationID, licenseKey, machineID string) (string, *domain.CertChain, error) {
	body, _ := json.Marshal(renewRequest{
		ActivationID:  activationID,
		LicenseKey:    licenseKey,
		MachineIDHash: machineID,
		SDK:           c.sdk,
	})

	return c.post(ctx, "/v1/renew", body)
}

// --- Machines ---

// machineRequest is renew's credentials, which the three machine calls share.
type machineRequest struct {
	ActivationID  string  `json:"activation_id"`
	LicenseKey    string  `json:"license_key"`
	MachineIDHash string  `json:"machine_id"`
	MachineName   string  `json:"machine_name,omitempty"`
	SDK           SDKInfo `json:"sdk"`
}

func (c *httpClient) Deactivate(ctx context.Context, activationID, licenseKey, machineID string) (bool, *time.Time, error) {
	var result struct {
		Released   bool       `json:"released"`
		SeatFreeAt *time.Time `json:"seat_free_at"`
	}
	err := c.call(ctx, "/v1/deactivate", machineRequest{
		ActivationID: activationID, LicenseKey: licenseKey, MachineIDHash: machineID, SDK: c.sdk,
	}, &result)
	var status *statusError
	// A 409 here is the seller's deactivation policy, never a seat limit.
	if errors.As(err, &status) && status.code == http.StatusConflict {
		return false, nil, &ports.DeactivationBlockedError{
			Reason: status.body.Reason, AvailableAt: status.body.AvailableAt, Message: status.body.Error,
		}
	}
	if err != nil {
		return false, nil, mapStatus(err)
	}
	return result.Released, result.SeatFreeAt, nil
}

func (c *httpClient) Machines(ctx context.Context, activationID, licenseKey, machineID string) ([]domain.Machine, error) {
	var result struct {
		Machines []domain.Machine `json:"machines"`
	}
	err := c.call(ctx, "/v1/machines", machineRequest{
		ActivationID: activationID, LicenseKey: licenseKey, MachineIDHash: machineID, SDK: c.sdk,
	}, &result)
	if err != nil {
		return nil, mapStatus(err)
	}
	return result.Machines, nil
}

func (c *httpClient) RenameMachine(ctx context.Context, activationID, licenseKey, machineID, name string) (string, error) {
	var result struct {
		MachineName string `json:"machine_name"`
	}
	err := c.call(ctx, "/v1/machines/rename", machineRequest{
		ActivationID: activationID, LicenseKey: licenseKey, MachineIDHash: machineID, MachineName: name, SDK: c.sdk,
	}, &result)
	if err != nil {
		return "", mapStatus(err)
	}
	return result.MachineName, nil
}

// --- shared POST helpers ---

type tokenResponse struct {
	Token        string           `json:"token"`
	ActivationID uuid.UUID        `json:"activation_id"`
	Chain        domain.CertChain `json:"chain"`
}

type errorResponse struct {
	Error       string     `json:"error"`
	Reason      string     `json:"reason"`
	AvailableAt *time.Time `json:"available_at"`
}

// statusError is a non-2xx answer, left for the caller to classify.
type statusError struct {
	code int
	body errorResponse
}

func (e *statusError) Error() string {
	if e.body.Error != "" {
		return "licenselatte: " + e.body.Error
	}
	return fmt.Sprintf("licenselatte: HTTP %d", e.code)
}

// call posts body as JSON to path and decodes a 2xx answer into out. A
// transport failure wraps ports.ErrNetworkError; any other status is a
// *statusError.
func (c *httpClient) call(ctx context.Context, path string, body any, out any) error {
	payload, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+path, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("licenselatte: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", ports.ErrNetworkError, err)
	}
	defer func(b io.ReadCloser) {
		_ = b.Close()
	}(resp.Body)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		status := &statusError{code: resp.StatusCode}
		_ = json.NewDecoder(resp.Body).Decode(&status.body)
		return status
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("licenselatte: decode response: %w", err)
	}
	return nil
}

// mapStatus turns a *statusError into the sentinel its status stands for and
// passes every other error through.
func mapStatus(err error) error {
	var status *statusError
	if !errors.As(err, &status) {
		return err
	}
	switch status.code {
	case http.StatusNotFound:
		return ports.ErrLicenseNotFound
	case http.StatusForbidden:
		return ports.ErrLicenseInactiveOrExpired
	case http.StatusConflict:
		return ports.ErrSeatLimitReached
	case http.StatusUnauthorized:
		return ports.ErrInvalidProjectKey
	default:
		return status
	}
}

func (c *httpClient) post(ctx context.Context, path string, body []byte) (string, *domain.CertChain, error) {
	var result tokenResponse
	if err := c.call(ctx, path, json.RawMessage(body), &result); err != nil {
		return "", nil, mapStatus(err)
	}
	if result.Token == "" {
		return "", nil, fmt.Errorf("licenselatte: server returned empty token")
	}
	if result.Chain.Daily == "" || result.Chain.Project == "" || result.Chain.Submaster == "" {
		return "", nil, fmt.Errorf("licenselatte: server returned empty chain")
	}

	return result.Token, &result.Chain, nil
}
