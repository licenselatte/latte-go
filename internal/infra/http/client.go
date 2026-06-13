package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/google/uuid"
	"github.com/licenselatte/latte-go/internal/core/domain"
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

func (c *httpClient) Activate(ctx context.Context, licenseKey, machineID string) (string, *domain.CertChain, error) {
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

func (c *httpClient) Renew(ctx context.Context, activationID, licenseKey, machineID string) (string, *domain.CertChain, error) {
	body, _ := json.Marshal(renewRequest{
		ActivationID:  activationID,
		LicenseKey:    licenseKey,
		MachineIDHash: machineID,
	})

	return c.post(ctx, "/v1/renew", body)
}

// --- shared POST helper ---

type tokenResponse struct {
	Token        string           `json:"token"`
	ActivationID uuid.UUID        `json:"activation_id"`
	Chain        domain.CertChain `json:"chain"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func (c *httpClient) post(ctx context.Context, path string, body []byte) (string, *domain.CertChain, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return "", nil, fmt.Errorf("licenselatte: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %w", ports.ErrNetworkError, err)
	}
	defer func(b io.ReadCloser) {
		_ = b.Close()
	}(resp.Body)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var errBody errorResponse
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		msg := errBody.Error
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		switch resp.StatusCode {
		case http.StatusNotFound:
			return "", nil, ports.ErrLicenseNotFound
		case http.StatusForbidden:
			return "", nil, ports.ErrLicenseInactiveOrExpired
		case http.StatusConflict:
			return "", nil, ports.ErrSeatLimitReached
		case http.StatusUnauthorized:
			return "", nil, ports.ErrInvalidProjectKey
		default:
			return "", nil, fmt.Errorf("licenselatte: %s", msg)
		}
	}

	var result tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", nil, fmt.Errorf("licenselatte: decode response: %w", err)
	}
	if result.Token == "" {
		return "", nil, fmt.Errorf("licenselatte: server returned empty token")
	}
	if result.Chain.Daily == "" || result.Chain.Project == "" || result.Chain.Submaster == "" {
		return "", nil, fmt.Errorf("licenselatte: server returned empty chain")
	}

	return result.Token, &result.Chain, nil
}
