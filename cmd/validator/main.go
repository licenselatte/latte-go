// validator is a low-level debug tool that activates a license and prints
// the raw JWT claims. Useful for verifying server-side token contents.
//
// Usage:
//
//	go run ./cmd/validator
package main

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/licenselatte/latte-go/internal/infra/crypto"
	latthttp "github.com/licenselatte/latte-go/internal/infra/http"
	"github.com/licenselatte/latte-go/internal/infra/validate"
	"github.com/licenselatte/latte-go/internal/infra/verify"
)

const (
	publicKeyHex = "6dcefb3bc8ca08b7be423ea0c95f819e130d42fbd8b718c23f89d8f041eb54fc"
	appID        = "pk_local_AHAK85389VQYXYB6S4BW66SKE53TWVTS"
	licenseKey   = "AHAK856T8PQS0245KDB1FEC9VXA998"
	machineID    = "test-machine-001"
)

func main() {
	pubKeyBytes, _ := hex.DecodeString(publicKeyHex)
	client := latthttp.NewHttpClient("http://localhost:8080", appID)

	key := crypto.SanitizeKey(licenseKey)
	fmt.Printf("Sanitized key: %s\n\n", key)

	fmt.Println("→ Activating…")
	token, chain, err := client.Activate(context.Background(), key, machineID)
	if err != nil {
		fmt.Printf("Activation error: %v\n", err)
		return
	}
	fmt.Printf("Token: %s\n\n", token)

	fmt.Println("→ Validating…")
	lic, err := verify.VerifyActivation(pubKeyBytes, token, chain)
	if err != nil {
		fmt.Printf("Verification error: %v\n", err)
		return
	}

	err = validate.Validate(lic, machineID)
	if err != nil {
		fmt.Printf("Validation error: %v\n", err)
		return
	}
	fmt.Printf("Key:           %s\n", lic.Key)
	fmt.Printf("ActivationID:  %s\n", lic.ActivationID)
	fmt.Printf("ProjectID:     %s\n", lic.ProjectID)
	fmt.Printf("ExpiresAt:     %s\n", lic.ExpiresAt)
	fmt.Printf("GracePeriod:   %s\n", lic.GracePeriod)

	fmt.Println("\n→ Renewing…")
	renewed, chain, err := client.Renew(context.Background(), lic.ActivationID, lic.Key, machineID)
	if err != nil {
		fmt.Printf("Renew error: %v\n", err)
		return
	}
	lic2, err := verify.VerifyActivation(pubKeyBytes, renewed, chain)
	if err != nil {
		fmt.Printf("Renew verification error: %v\n", err)
		return
	}

	err = validate.Validate(lic2, machineID)
	if err != nil {
		fmt.Printf("Renew validation error: %v\n", err)
		return
	}

	fmt.Printf("Renewed token valid — ExpiresAt: %s\n", lic2.ExpiresAt)
}
