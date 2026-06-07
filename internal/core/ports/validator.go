package ports

import "github.com/licenselatte/latte-go/internal/core/domain"

// Validator verifies a JWT token against the server's public key and the
// current machine ID, returning a typed License on success.
type Validator interface {
	Validate(token string, machineID string) (*domain.License, error)
}
