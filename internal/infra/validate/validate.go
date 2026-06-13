package validate

import (
	"fmt"
	"strings"
	"time"

	"github.com/licenselatte/latte-go/internal/core/domain"
	"github.com/licenselatte/latte-go/internal/core/ports"
)

const (
	maxAge = 365 * 24 * time.Hour
)

func Validate(license *domain.License, machineID string) error {
	if license.IssuedAt.IsZero() {
		return fmt.Errorf("invalid license: issued_at is zero")
	}
	if license.ExpiresAt.IsZero() {
		return fmt.Errorf("invalid license: expires_at is zero")
	}
	if license.GracePeriod.Seconds() <= 0 {
		return fmt.Errorf("invalid license: grace_period is zero or negative")
	}
	if !strings.EqualFold(license.MachineIDHash, machineID) {
		return fmt.Errorf("invalid license: machine_id does not match")
	}
	if license.ExpiresAt.Before(license.IssuedAt) {
		return fmt.Errorf("invalid license: expires_at is before issued_at")
	}

	// perpetual_fixed tokens never expire and have no grc check.
	// The only requirement is that we haven't somehow passed year 2099.
	if license.LicenseType == "perpetual_fixed" {
		if time.Now().After(license.ExpiresAt) {
			return ports.ErrLicenseInactiveOrExpired
		}
		return nil
	}

	offlineDeadline := license.IssuedAt.Add(license.GracePeriod)

	now := time.Now()
	if now.After(license.ExpiresAt) {
		return ports.ErrLicenseInactiveOrExpired
	}

	if now.After(offlineDeadline) {
		return ports.ErrGracePeriodExpired
	}

	if now.Sub(license.IssuedAt) > maxAge {
		return ports.ErrLicenseTooOld
	}

	return nil
}
