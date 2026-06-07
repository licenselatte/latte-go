package storage

import (
	"bufio"
	"fmt"
	"os"
	"time"
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
}

// map app id to token
func (fs *FileStorage) parseFile() (*activationRecord, error) {
	file, err := os.Open(fs.location)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := bufio.NewReader(file)

	var timestamp int64
	var token string
	n, err := fmt.Fscanf(reader, "%d:%s", &timestamp, &token)
	if err != nil {
		return nil, err
	}

	if n != 2 {
		return nil, fmt.Errorf("invalid file format")
	}

	return &activationRecord{
		Timestamp: timestamp,
		Token:     token,
	}, nil

}

func (fs *FileStorage) writeFile(record *activationRecord) error {
	file, err := os.Create(fs.location)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	line := fmt.Sprintf("%d:%s", record.Timestamp, record.Token)
	_, err = writer.WriteString(line)
	if err != nil {
		return err
	}
	writer.Flush()

	return nil
}

func (fs *FileStorage) SaveToken(token string) error {
	record := &activationRecord{
		Timestamp: time.Now().Unix(),
		Token:     token,
	}

	if err := fs.writeFile(record); err != nil {
		return err
	}

	return nil
}

func (fs *FileStorage) LoadToken() (string, error) {
	record, err := fs.parseFile()
	if err != nil {
		return "", err
	}

	return record.Token, nil
}
