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

	// Metadata contains the public metadata configured for the license in the dashboard
	Metadata map[string]string

	// Entitlements is the typed feature map the seller signed into this
	// licence: a flat map whose values are bool or int64 and nothing else.
	// Read it with Can and Limit rather than indexing it directly, unless
	// you want to enumerate what was granted.
	//
	// Nil means the token carried no `ent` claim at all, which is a
	// different thing from an empty map and is what HasEntitlements
	// reports. See entitlements.go for the full contract.
	Entitlements map[string]any
}

// Can reports whether the boolean entitlement named by key is present and
// true.
//
// A key that is absent, or that holds an integer rather than a boolean,
// answers false. There is no coercion across kinds: Can on an integer
// entitlement is false even when that integer is non-zero, because a rule
// that read "nonzero is true" is one five SDKs would eventually disagree
// about.
func (l *License) Can(key string) bool {
	v, ok := l.Entitlements[key].(bool)
	return ok && v
}

// Limit returns the integer entitlement named by key, and whether it was
// present.
//
// The unlimited sentinel is returned as-is: compare the result against
// Unlimited rather than testing for a negative number. A key that is absent,
// or that holds a boolean rather than an integer, misses — Limit on a
// boolean returns (0, false), not 1 or 0.
func (l *License) Limit(key string) (int64, bool) {
	v, ok := l.Entitlements[key].(int64)
	if !ok {
		return 0, false
	}
	return v, true
}

// HasEntitlements reports whether the activation token carried an `ent`
// claim at all — including an empty one, which is why this is not a length
// check.
//
// It exists for one job: letting an application fall back to its
// pre-entitlements behaviour for the one release it takes an installed base
// to renew. Absence denies, so without this probe, shipping Can() before
// setting values in the dashboard switches the feature off for every
// customer holding an older cached token. See entitlements.go.
func (l *License) HasEntitlements() bool {
	return l.Entitlements != nil
}
