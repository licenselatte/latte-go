package ports

import (
	"context"
	"errors"
	"fmt"
)

type InvalidLicenseError struct {
	err string
}

func (i *InvalidLicenseError) Error() string {
	return i.err
}

func NewInvalidLicenseError(message string) error {
	return &InvalidLicenseError{
		err: fmt.Sprintf("licenselatte: %s", message),
	}
}

var (
	ErrNetworkError             = errors.New("licenselatte: network error")
	ErrLicenseNotFound          = NewInvalidLicenseError("license not found")
	ErrLicenseInactiveOrExpired = NewInvalidLicenseError("license inactive or expired")
	ErrSeatLimitReached         = NewInvalidLicenseError("seat limit reached")
	ErrInvalidProjectKey        = NewInvalidLicenseError("invalid project key")
	ErrGracePeriodExpired       = NewInvalidLicenseError("grace period expired")
)

// Activator performs the initial activation of a license key on this machine.
type Activator interface {
	Activate(ctx context.Context, licenseKey, machineID string) (token string, err error)
}

// Renewer refreshes an existing activation token while the license is still valid.
// It requires the activation_id from the previously issued token.
type Renewer interface {
	Renew(ctx context.Context, activationID, licenseKey, machineID string) (token string, err error)
}
