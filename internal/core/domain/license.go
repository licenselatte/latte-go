package domain

import "time"

// License is the validated, in-memory representation of an active license token.
// It is produced by the Validator and consumed by the SDK's public API.
type License struct {
	// Key is the raw license key (no hyphens), as sent to and from the API.
	Key string

	// ActivationID is the server-assigned UUID for this device's activation slot.
	// Required for token renewal.
	ActivationID string

	// ProjectID is the UUID of the project this license belongs to.
	ProjectID string

	// IssuedAt is the timestamp when the server issued the license.
	IssuedAt time.Time

	// ExpiresAt is the hard expiry from the JWT exp claim.
	// For perpetual_fixed licenses this is year 2099.
	ExpiresAt time.Time

	// GracePeriod is the offline tolerance window after ExpiresAt.
	// While within the grace window, the SDK continues working without a network call.
	GracePeriod time.Duration

	// LicenseType is the policy type: "perpetual_fixed", "perpetual", or "expiring".
	LicenseType string

	// Claims is the full JWT payload, available for custom fields the integrator
	// may embed via license metadata.
	Claims map[string]interface{}
}

// IsValid reports whether the license is currently usable (not past grace period).
func (l *License) IsValid() bool {
	return time.Since(l.IssuedAt) > l.GracePeriod
}
