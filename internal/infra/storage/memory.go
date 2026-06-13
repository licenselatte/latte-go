package storage

import (
	"github.com/licenselatte/latte-go/internal/core/domain"
	"github.com/licenselatte/latte-go/internal/core/ports"
)

type MemoryStorage struct {
	token string
	chain *domain.CertChain
}

func NewMemoryStorage() ports.Storage {
	return &MemoryStorage{}
}

func (s *MemoryStorage) SaveToken(token string, chain *domain.CertChain) error {
	s.token = token
	s.chain = chain
	return nil
}

func (s *MemoryStorage) LoadToken() (string, *domain.CertChain, error) {
	return s.token, s.chain, nil
}
