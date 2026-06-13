package ports

import "github.com/licenselatte/latte-go/internal/core/domain"

type Storage interface {
	SaveToken(token string, chain *domain.CertChain) error
	LoadToken() (string, *domain.CertChain, error)
}
