package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/licenselatte/sdk-go/internal/infra/crypto"
	"github.com/licenselatte/sdk-go/internal/infra/http"
	"github.com/licenselatte/sdk-go/internal/infra/storage"
)

const publicKeyHex = "6dcefb3bc8ca08b7be423ea0c95f819e130d42fbd8b718c23f89d8f041eb54fc"

func main() {
	pubKeyBytes, _ := hex.DecodeString(publicKeyHex)
	pubKey := ed25519.PublicKey(pubKeyBytes)

	validator := crypto.NewEd25519Validator(pubKey, "licenselatte")

	appId := "pk_local_BW7X9HRMTHA2B2PN7G5SXBN646PW4321"
	appIdParts := strings.Split(appId, "_")
	shortId := appIdParts[len(appIdParts)-1][:6]

	appIdValid := crypto.ValidateKey(appIdParts[2], 4)
	if !appIdValid {
		fmt.Println("invalid AppID")
		return
	}

	dir, err := os.UserConfigDir()
	valid := true
	if err == nil {
		dir = filepath.Join(dir, "LicenseLatte")
		if err := os.MkdirAll(dir, 0755); err != nil {
			valid = false
		}
		dir = filepath.Join(dir, fmt.Sprintf("%s.latte", appIdParts[2]))
	}
	if !valid {
		dir = "./.licenselatte"
		if err := os.MkdirAll(dir, 0755); err != nil {
			panic("could not create storage directory: " + err.Error())
		}
		dir = filepath.Join(dir, "token.latte")
	}

	fmt.Printf("storage dir: %s\n", dir)
	s := storage.NewFileStorage(dir)

	client := http.NewHttpClient("http://localhost:8080")

	key := crypto.SanitizeKey("BW7X9-HZYMB-AT12Z-ZW40K-YRSBB-XRCDC")

	if key[:6] != shortId {
		fmt.Println("invalid key")
		return
	}

	valid = crypto.ValidateKey(key[6:], 2)
	if !valid {
		fmt.Println("invalid key")
		return
	}

	if token, err := s.LoadToken(); err == nil {
		fmt.Printf("token:%s\n", token)
	}

	t, err := client.Activate(context.Background(), key, "aaa")
	if err != nil {
		panic("could not activate: " + err.Error())
	}
	claims, err2 := validator.Validate(t, "aaa")
	fmt.Printf("token:%s\nclaims:%+v\nerr:%v\nerr2:%v\n\n", t, claims, err, err2)

	if err == nil {
		if err := s.SaveToken(t); err != nil {
			panic("could not save token: " + err.Error())
		}
	}

}
