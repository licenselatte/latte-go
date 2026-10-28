package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/licenselatte/latte-go/internal/core/domain"
)

type FileStorage struct {
	location string
}

func NewFileStorage(location string) *FileStorage {
	return &FileStorage{location: location}
}

type activationRecord struct {
	Timestamp int64  `json:"timestamp"`
	Token     string `json:"token"`
	Submaster string `json:"submaster"`
	Project   string `json:"project"`
	Daily     string `json:"daily"`
}

func (fs *FileStorage) parseFile() (*activationRecord, error) {
	data, err := os.ReadFile(fs.location)
	if err != nil {
		return nil, err
	}

	line := strings.TrimSpace(string(data))

	var record activationRecord
	if err := json.Unmarshal([]byte(line), &record); err != nil {
		return nil, fmt.Errorf("invalid file format: %w", err)
	}

	return &record, nil
}

func (fs *FileStorage) writeFile(record *activationRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}

	// A temp file renamed over the cache keeps readers from seeing a partial
	// write and concurrent writers from interleaving.
	tmp, err := os.CreateTemp(filepath.Dir(fs.location), filepath.Base(fs.location)+".*.tmp")
	if err != nil {
		return err
	}

	_, err = tmp.Write(data)
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), fs.location)
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
	}

	return err
}

func (fs *FileStorage) SaveToken(token string, chain *domain.CertChain) error {
	record := &activationRecord{
		Timestamp: time.Now().Unix(),
		Token:     token,
	}

	if chain != nil {
		record.Submaster = chain.Submaster
		record.Project = chain.Project
		record.Daily = chain.Daily
	}

	if err := fs.writeFile(record); err != nil {
		return err
	}

	return nil
}

func (fs *FileStorage) LoadToken() (string, *domain.CertChain, error) {
	record, err := fs.parseFile()
	if err != nil {
		return "", nil, err
	}

	chain := &domain.CertChain{
		Submaster: record.Submaster,
		Project:   record.Project,
		Daily:     record.Daily,
	}

	return record.Token, chain, nil
}
