package storage

import "github.com/licenselatte/sdk-go/internal/core/ports"

type MemoryStorage struct {
	token string
}

func NewMemoryStorage() ports.Storage {
	return &MemoryStorage{}
}

func (s *MemoryStorage) SaveToken(token string) error {
	s.token = token
	return nil
}

func (s *MemoryStorage) LoadToken() (string, error) {
	return s.token, nil
}
