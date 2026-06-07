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

	publicKeyHex = "6dcefb3bc8ca08b7be423ea0c95f819e130d42fbd8b718c23f89d8f041eb54fc"

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
