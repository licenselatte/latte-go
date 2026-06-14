package latte

import "time"

type appEnv string

const (
	envLive  appEnv = "live"
	envTest  appEnv = "test"
	envLocal appEnv = "local"
)

const (
	publicURL = "https://api.licenselatte.com"
	testURL   = "https://test.api.licenselatte.com"
	localURL  = "http://localhost:8080"

	// Root master public key (Ed25519) used to verify the server's certificate chain. This key is hardcoded in the SDK and should not be changed.
	// Fingerprint: 49C1CA77D17984E0D25C0994D626409AD567D479
	// Verify: gpg --recv-keys 49C1CA77D17984E0D25C0994D626409AD567D479
	publicKeyHex = "6773cdfdfb7fc44f13f097449b715e7147a2d73f525d9f09a8d25229e458a2fb"

	// minRenewalTime is the minimum time before the SDK can execute a renew request agains the server
	minRenewalTime = 5 * time.Minute
	// maxRenewalTime is the maximum time it takes for the SDK to execute a renew request against the server
	maxRenewalTime = 60 * time.Minute
)

const (
	licenseTypePerpetualFixed = "perpetual_fixed"
	licenseTypePerpetual      = "perpetual"
	licenseTypeExpiring       = "expiring"
)
