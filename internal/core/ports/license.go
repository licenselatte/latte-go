package ports

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/licenselatte/latte-go/internal/core/domain"
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
	ErrLicenseTooOld            = NewInvalidLicenseError("license too old")
)

// Activator performs the initial activation of a license key on this machine.
type Activator interface {
	Activate(ctx context.Context, licenseKey, machineID string) (token string, chain *domain.CertChain, err error)
}

// Renewer refreshes an existing activation token while the license is still valid.
// It requires the activation_id from the previously issued token.
type Renewer interface {
	Renew(ctx context.Context, activationID, licenseKey, machineID string) (token string, chain *domain.CertChain, err error)
}

// DeactivationBlockedError is the seller's deactivation policy refusing a
// release: a cooldown or a yearly cap. Message is written for the end user.
type DeactivationBlockedError struct {
	Reason      string
	AvailableAt *time.Time
	Message     string
}

func (e *DeactivationBlockedError) Error() string {
	return "licenselatte: " + e.Message
}

// MachineManager releases, lists and names this machine's activation. Every
// call proves the machine with the same three values Renew sends.
type MachineManager interface {
	Deactivate(ctx context.Context, activationID, licenseKey, machineID string) (released bool, seatFreeAt *time.Time, err error)
	Machines(ctx context.Context, activationID, licenseKey, machineID string) ([]domain.Machine, error)
	RenameMachine(ctx context.Context, activationID, licenseKey, machineID, name string) (string, error)
}
