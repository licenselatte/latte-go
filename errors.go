package latte

import "errors"

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
)

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
