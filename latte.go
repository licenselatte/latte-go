package latte

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/denisbrodbeck/machineid"
	"github.com/licenselatte/sdk-go/internal/core/ports"
	"github.com/licenselatte/sdk-go/internal/infra/crypto"
	"github.com/licenselatte/sdk-go/internal/infra/http"
	"github.com/licenselatte/sdk-go/internal/infra/storage"
)

const appIDPrefix = "pk"

type appIDType string

const (
	appIDTypeTest  appIDType = "test"
	appIDTypeProd  appIDType = "live"
	appIDTypeLocal appIDType = "local"
)

type Config struct {
	AppID string
}

const publicURL = "https://api.licenselatte.com"
const testURL = "https://test.api.licenselatte.com"
const localURL = "http://localhost:8080"

const publicKeyHex = "6dcefb3bc8ca08b7be423ea0c95f819e130d42fbd8b718c23f89d8f041eb54fc"

type SDK struct {
	url        string
	appID      string
	appKeyType appIDType
	appKey     string
	activator  ports.Activator
	validator  ports.Validator
	store      ports.Storage
	machineID  string
}

func (c *Config) validateAppID() (appIDType, string, error) {
	var keyType, key string
	parts := strings.Split(c.AppID, "_")
	if len(parts) != 3 {
		return "", "", fmt.Errorf("invalid AppID format")
	}

	if parts[0] != appIDPrefix {
		return "", "", fmt.Errorf("invalid AppID prefix")
	}

	keyType = parts[1]
	key = parts[2]

	if len(key) != 32 {
		return "", "", fmt.Errorf("invalid AppID format")
	}

	if !crypto.ValidateKey(key, 4) {
		return "", "", fmt.Errorf("invalid AppID")
	}

	if keyType != string(appIDTypeTest) && keyType != string(appIDTypeProd) && keyType != string(appIDTypeLocal) {
		return "", "", fmt.Errorf("invalid AppID type")
	}

	return appIDType(keyType), key, nil
}

func New(config *Config) (*SDK, error) {
	keyType, key, err := config.validateAppID()
	if err != nil {
		return nil, err
	}

	var url string
	switch keyType {
	case appIDTypeTest:
		url = testURL
	case appIDTypeProd:
		url = publicURL
	case appIDTypeLocal:
		url = localURL
	default:
		panic("invalid AppID type")
	}

	activator := http.NewHttpClient(url, config.AppID)

	pubKeyBytes, _ := hex.DecodeString(publicKeyHex)
	pubKey := ed25519.PublicKey(pubKeyBytes)
	validator := crypto.NewEd25519Validator(pubKey, "licenselatte")

	dir, err := os.UserConfigDir()
	valid := true
	if err == nil {
		dir = filepath.Join(dir, "LicenseLatte")
		if err := os.MkdirAll(dir, 0755); err != nil {
			valid = false
		}
	}
	if !valid {
		dir = "./.licenselatte"
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("could not create storage directory: %s", err.Error())
		}
	}

	dir = filepath.Join(dir, fmt.Sprintf("%s.latte", key))

	s := storage.NewFileStorage(dir)

	machineID, err := machineid.ProtectedID("licenselatte_" + key)
	if err != nil {
		return nil, fmt.Errorf("could not get machine ID: %s", err.Error())
	}

	return &SDK{
		url:        url,
		appID:      config.AppID,
		appKeyType: keyType,
		appKey:     key,
		activator:  activator,
		validator:  validator,
		store:      s,
		machineID:  machineID,
	}, nil
}

func (s *SDK) Activate(key string) (map[string]interface{}, error) {
	return s.ActivateWithContext(context.Background(), key)
}

func (s *SDK) ActivateWithContext(ctx context.Context, key string) (map[string]interface{}, error) {
	key = crypto.SanitizeKey(key)
	if key[:6] != s.appKey[:6] {
		return map[string]interface{}{}, fmt.Errorf("invalid AppID")
	}

	data := key[6:]
	if !crypto.ValidateKey(data, 2) {
		return map[string]interface{}{}, fmt.Errorf("invalid AppID")
	}

	token, err := s.store.LoadToken()
	if err == nil {
		claims, err := s.validator.Validate(token, s.machineID)
		if err == nil {
			go s.silentCheck(key)
			return claims, nil
		}
	}

	token, err = s.activator.Activate(ctx, key, s.machineID)
	if err != nil {
		return map[string]interface{}{}, err
	}

	claims, err := s.validator.Validate(token, s.machineID)
	if err != nil {
		return map[string]interface{}{}, err
	}

	if err := s.store.SaveToken(token); err != nil {
		return map[string]interface{}{}, err
	}

	return claims, nil
}

func (s *SDK) silentCheck(key string) {
	token, err := s.activator.Activate(context.Background(), key, s.machineID)
	if err != nil {
		return
	}
	_, err = s.validator.Validate(token, s.machineID)
	if err != nil {
		return
	}
	_ = s.store.SaveToken(token)
}
