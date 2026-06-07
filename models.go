package latte

import "time"

// License is a validated, active license returned by Activate and Check.
type License struct {
	// Key is the raw license key (no hyphens).
	Key string

	// ActivationID is the server UUID for this machine's activation slot.
	ActivationID string

	// ProjectID is the UUID of the owning project.
	ProjectID string

	// IssuedAt is the timestamp when the server issued the license.
	IssuedAt time.Time

	// ExpiresAt is the hard expiry of the current token (far-future for perpetual).
	ExpiresAt time.Time

	// GracePeriod is the offline tolerance window after ExpiresAt.
	GracePeriod time.Duration

	// InGracePeriod is true when the token has expired but the grace window
	// has not elapsed. The application should surface a "please reconnect" warning.
	InGracePeriod bool

	// LicenseType is "perpetual_fixed", "perpetual", or "expiring".
	LicenseType string

	// Claims is the full JWT payload for access to any custom metadata.
	Claims map[string]interface{}
}
