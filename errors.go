package latte

import (
	"errors"
	"time"
)

// Sentinel errors returned by Activate, Check, and Renew.
var (
	// ErrInvalidKey is returned when the provided license key fails format/checksum validation.
	ErrInvalidKey = errors.New("licenselatte: invalid license key")

	// ErrLicenseExpired is returned when the token is past its grace period.
	ErrLicenseExpired = errors.New("licenselatte: license expired")

	// ErrNotActivated is returned by Check when no token has been stored yet.
	ErrNotActivated = errors.New("licenselatte: not activated on this machine")

	// ErrSeatLimit is returned when all activation slots on the license are occupied.
	ErrSeatLimit = errors.New("licenselatte: activation seat limit reached")

	// ErrLicenseNotFound is returned when the provided license key is valid but not found on the server.
	ErrLicenseNotFound = errors.New("licenselatte: license not found")

	// ErrInvalidProjectKey is returned when the provided project key is invalid, this is a config error.
	ErrInvalidProjectKey = errors.New("licenselatte: invalid project key")

	// ErrDeactivationBlocked is matched by the *DeactivationBlockedError
	// Deactivate returns when the seller's deactivation policy refuses it.
	ErrDeactivationBlocked = errors.New("licenselatte: deactivation blocked")
)

// DeactivationBlockedError is Deactivate refused by the seller's deactivation
// policy: a machine on this licence was released too recently, or the licence
// has used its releases for the year. Nothing was released and the cached
// token is kept.
type DeactivationBlockedError struct {
	// Reason is "deactivation_cooldown" or "deactivation_limit_reached".
	Reason string
	// AvailableAt is when a release becomes possible, nil when not known.
	AvailableAt *time.Time
	// Message explains the refusal and is written to be shown to the user.
	Message string
}

func (e *DeactivationBlockedError) Error() string { return "licenselatte: " + e.Message }

func (e *DeactivationBlockedError) Is(target error) bool { return target == ErrDeactivationBlocked }

// Sentinel errors returned by the internal app id parser. They are config errors.
var (
	// ErrInvalidAppID is returned when the provided AppID is invalid.
	ErrInvalidAppID = errors.New("licenselatte: invalid AppID")

	// ErrUnknownEnvironment is returned when the provided environment is unknown. Expected values are "live", "test", or "local".
	ErrUnknownEnvironment = errors.New("licenselatte: unknown environment")

	// ErrInvalidAppIDKeySegment is returned when the provided AppID key segment is invalid.
	ErrInvalidAppIDKeySegment = errors.New("licenselatte: invalid app id key segment")

	// ErrInvalidAppIDChecksum is returned when the provided AppID checksum is invalid.
	ErrInvalidAppIDChecksum = errors.New("licenselatte: invalid app id checksum")
)

// Sentinel errors returned by the SDK instance creation. They are runtime errors.
var (
	// ErrStorageInitFailed is returned when the SDK cannot initialize the storage.
	ErrStorageInitFailed = errors.New("licenselatte: cannot initialize storage")

	// ErrMachineIDFailed is returned when the SDK cannot determine the machine ID.
	ErrMachineIDFailed = errors.New("licenselatte: cannot determine machine ID")
)
