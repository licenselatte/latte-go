// sdktest is a manual integration test binary.
// Run it against a local LicenseLatte API to verify the full activate→renew cycle.
//
// Usage:
//
//	LICENSE_PRIVATE_KEY=... go run ./cmd/sdktest
package main

import (
	"fmt"
	"time"

	latte "github.com/licenselatte/latte-go"
)

// Replace these with real values from your local dashboard.
const (
	appID      = "pk_local_AHAK85389VQYXYB6S4BW66SKE53TWVTS"
	licenseKey = "AHAK85T628WZ639CMVHF8TNDDX260Z"
)

func main() {
	sdk, err := latte.New(&latte.Config{AppID: appID})
	if err != nil {
		panic("failed to init SDK: " + err.Error())
	}

	fmt.Println("→ Activating…")
	lic, err := sdk.Activate(licenseKey)
	if err != nil {
		panic("activation failed: " + err.Error())
	}

	printLicense("Activate", lic)

	fmt.Println("\n→ Checking stored token (offline)…")
	lic, err = sdk.Check()
	if err != nil {
		fmt.Println("  Check error:", err)
	} else {
		printLicense("Check", lic)
	}

	fmt.Println("\n→ Polling every 15 s (Ctrl-C to stop)…")
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		lic, err = sdk.Check()
		if err != nil {
			fmt.Println("  license invalid:", err)
			continue
		}
		grace := ""
		if lic.InGracePeriod {
			grace = " [GRACE PERIOD]"
		}
		fmt.Printf("  OK — expires %s%s\n", lic.ExpiresAt.Format(time.RFC3339), grace)
	}
}

func printLicense(label string, lic *latte.License) {
	fmt.Printf("  [%s]\n", label)
	fmt.Printf("  Key:           %s\n", lic.Key)
	fmt.Printf("  ActivationID:  %s\n", lic.ActivationID)
	fmt.Printf("  ProjectID:     %s\n", lic.ProjectID)
	fmt.Printf("  IssuedAt:      %s\n", lic.IssuedAt.Format(time.RFC3339))
	fmt.Printf("  ExpiresAt:     %s\n", lic.ExpiresAt.Format(time.RFC3339))
	fmt.Printf("  GracePeriod:   %s\n", lic.GracePeriod)
	fmt.Printf("  InGracePeriod: %v\n", lic.InGracePeriod)
	fmt.Printf("  LicenseType:   %s\n", lic.LicenseType)
	fmt.Printf("  Claims:        %v\n", lic.Claims)
}
