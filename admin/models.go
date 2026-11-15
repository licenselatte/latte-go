package admin

import (
	"encoding/json"
	"time"
)

// Status is a license's lifecycle state.
type Status string

const (
	StatusActive              Status = "active"
	StatusExpired             Status = "expired"
	StatusRevoked             Status = "revoked"
	StatusSuspended           Status = "suspended"
	StatusPendingDeactivation Status = "pending_deactivation"
)

// License is a license as the admin API reports it.
type License struct {
	ID             string         `json:"id"`
	ProjectID      string         `json:"project_id"`
	PolicyID       string         `json:"policy_id"`
	LicenseKey     string         `json:"license_key"`
	Status         Status         `json:"status"`
	ExpiresAt      *time.Time     `json:"expires_at"`
	Metadata       map[string]any `json:"metadata"`
	ClientMetadata map[string]any `json:"client_metadata"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`

	// Raw is the whole JSON object, including fields this version does not model.
	Raw map[string]json.RawMessage `json:"-"`
}

func (l *License) UnmarshalJSON(b []byte) error {
	type plain License
	if err := json.Unmarshal(b, (*plain)(l)); err != nil {
		return err
	}
	return json.Unmarshal(b, &l.Raw)
}

// LicenseList is one page of ListLicenses. Total counts the whole project.
type LicenseList struct {
	Licenses []License `json:"licenses"`
	Total    int       `json:"total"`
}

// Policy is a license policy, with the seat cap and offline window as enforced.
type Policy struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	LicenseType      string    `json:"license_type"`
	ExpiryMode       string    `json:"expiry_mode"`
	ExpiryDate       *string   `json:"expiry_date"`
	ExpiryDays       *int      `json:"expiry_days"`
	MaxActivations   *int      `json:"max_activations"`
	GracePeriodHours *int      `json:"grace_period_hours"`
	CreatedAt        time.Time `json:"created_at"`

	// Raw is the whole JSON object, including fields this version does not model.
	Raw map[string]json.RawMessage `json:"-"`
}

func (p *Policy) UnmarshalJSON(b []byte) error {
	type plain Policy
	if err := json.Unmarshal(b, (*plain)(p)); err != nil {
		return err
	}
	return json.Unmarshal(b, &p.Raw)
}

// Activation is one machine's seat on a license.
type Activation struct {
	ID            string         `json:"id"`
	Status        string         `json:"status"`
	MachineIDHash string         `json:"machine_id_hash"`
	ActivatedAt   *time.Time     `json:"activated_at"`
	LastRenewedAt *time.Time     `json:"last_renewed_at"`
	DeactivatedAt *time.Time     `json:"deactivated_at"`
	SeatHeldUntil *time.Time     `json:"seat_held_until"`
	SDK           any            `json:"sdk"`
	Metadata      map[string]any `json:"metadata"`

	// Raw is the whole JSON object, including fields this version does not model.
	Raw map[string]json.RawMessage `json:"-"`
}

func (a *Activation) UnmarshalJSON(b []byte) error {
	type plain Activation
	if err := json.Unmarshal(b, (*plain)(a)); err != nil {
		return err
	}
	return json.Unmarshal(b, &a.Raw)
}

// IssueLicenseParams is the body of IssueLicense. Only PolicyID is required.
// Setting CustomerEmail also emails the buyer their key, when the project allows it.
type IssueLicenseParams struct {
	PolicyID       string         `json:"policy_id"`
	CustomerEmail  string         `json:"customer_email,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
	ClientMetadata map[string]any `json:"client_metadata,omitempty"`
}

// ListLicensesParams filters ListLicenses. Zero values are not sent.
type ListLicensesParams struct {
	Limit         int
	Offset        int
	CustomerEmail string
	Status        Status
}

// UpdateLicenseParams is the body of UpdateLicense. A nil map or ExpiresAt
// leaves that field alone; a non-nil map replaces the stored object wholesale
// (an empty map clears it). ClearExpiresAt sends a JSON null for expires_at
// and wins over ExpiresAt.
type UpdateLicenseParams struct {
	Metadata       map[string]any
	ClientMetadata map[string]any
	ExpiresAt      *time.Time
	ClearExpiresAt bool
}

func (p UpdateLicenseParams) MarshalJSON() ([]byte, error) {
	m := map[string]any{}
	if p.Metadata != nil {
		m["metadata"] = p.Metadata
	}
	if p.ClientMetadata != nil {
		m["client_metadata"] = p.ClientMetadata
	}
	if p.ClearExpiresAt {
		m["expires_at"] = nil
	} else if p.ExpiresAt != nil {
		m["expires_at"] = p.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return json.Marshal(m)
}
