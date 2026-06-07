package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/licenselatte/latte-go/internal/core/ports"
)

type httpClient struct {
	endpoint   string
	projectKey string
	http       *http.Client
}

// NewHttpClient returns an Activator + Renewer backed by the LicenseLatte HTTP API.
func NewHttpClient(endpoint string, projectKey string) interface {
	ports.Activator
	ports.Renewer
} {
	return &httpClient{
		endpoint:   endpoint,
		projectKey: projectKey,
		http:       &http.Client{},
	}
}

// --- Activate ---

type activateRequest struct {
	ProjectKey    string `json:"project_key"`
	LicenseKey    string `json:"license_key"`
	MachineIDHash string `json:"machine_id"`
}

type activateResponse struct {
	Token string `json:"token"`
}

func (c *httpClient) Activate(ctx context.Context, licenseKey, machineID string) (string, error) {
	body, _ := json.Marshal(activateRequest{
		ProjectKey:    c.projectKey,
		LicenseKey:    licenseKey,
		MachineIDHash: machineID,
	})

	return c.post(ctx, "/v1/activate", body)
}

// --- Renew ---

type renewRequest struct {
	ActivationID  string `json:"activation_id"`
	LicenseKey    string `json:"license_key"`
	MachineIDHash string `json:"machine_id"`
}

func (c *httpClient) Renew(ctx context.Context, activationID, licenseKey, machineID string) (string, error) {
	body, _ := json.Marshal(renewRequest{
		ActivationID:  activationID,
		LicenseKey:    licenseKey,
		MachineIDHash: machineID,
	})

	return c.post(ctx, "/v1/renew", body)
}

// --- shared POST helper ---

type tokenResponse struct {
	Token string `json:"token"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func (c *httpClient) post(ctx context.Context, path string, body []byte) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("licenselatte: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ports.ErrNetworkError, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var errBody errorResponse
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		msg := errBody.Error
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		switch resp.StatusCode {
		case http.StatusNotFound:
			return "", ports.ErrLicenseNotFound
		case http.StatusForbidden:
			return "", ports.ErrLicenseInactiveOrExpired
		case http.StatusConflict:
			return "", ports.ErrSeatLimitReached
		case http.StatusUnauthorized:
			return "", ports.ErrInvalidProjectKey
		default:
			return "", fmt.Errorf("licenselatte: %s", msg)
		}
	}

	var result tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("licenselatte: decode response: %w", err)
	}
	if result.Token == "" {
		return "", fmt.Errorf("licenselatte: server returned empty token")
	}

	return result.Token, nil
}
