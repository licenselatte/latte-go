package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
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
	Timestamp int64
	Token     string
	Submaster string
	Project   string
	Daily     string
}

func (fs *FileStorage) parseFile() (*activationRecord, error) {
	data, err := os.ReadFile(fs.location)
	if err != nil {
		return nil, err
	}

	line := strings.TrimSpace(string(data))

	// Try JSON first
	var record activationRecord
	if err := json.Unmarshal([]byte(line), &record); err == nil {
		return &record, nil
	}

	// Fall back to legacy "timestamp:token" format
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid file format")
	}

	ts, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid timestamp: %w", err)
	}

	return &activationRecord{
		Timestamp: ts,
		Token:     parts[1],
	}, nil
}

func (fs *FileStorage) writeFile(record *activationRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}

	return os.WriteFile(fs.location, data, 0600)
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
