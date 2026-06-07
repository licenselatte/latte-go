package http

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/licenselatte/sdk-go/internal/core/ports"
)

type licenseActivationRequest struct {
	ProjectKey    string `json:"project_key"`
	LicenseKey    string `json:"license_key"`
	MachineIDHash string `json:"machine_id"`
}

type licenseActivationResponse struct {
	Token string `json:"token"`
}

type httpClient struct {
	endpoint   string
	projectKey string
}

func NewHttpClient(endpoint string, projectKey string) ports.Activator {
	return &httpClient{
		endpoint:   endpoint,
		projectKey: projectKey,
	}
}

const activatePath = "/v1/activate"

func (c *httpClient) Activate(ctx context.Context, key string, machineID string) (string, error) {
	activationReq := &licenseActivationRequest{
		ProjectKey:    c.projectKey,
		LicenseKey:    key,
		MachineIDHash: machineID,
	}

	body, err := json.Marshal(activationReq)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+activatePath, bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var respBody licenseActivationResponse
	err = json.NewDecoder(resp.Body).Decode(&respBody)
	if err != nil {
		return "", err
	}

	return respBody.Token, nil
}
