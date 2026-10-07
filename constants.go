package latte

import (
	"crypto/ed25519"
	"encoding/hex"
	"time"
)

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

	// sdkVersion is reported to the API on every request, with sdkLanguage.
	sdkVersion  = "1.5.0"
	sdkLanguage = "go"

	// minRenewalTime is the minimum time before the SDK can execute a renew request agains the server
	minRenewalTime = 5 * time.Minute
	// maxRenewalTime is the maximum time it takes for the SDK to execute a renew request against the server
	maxRenewalTime = 60 * time.Minute
)

// masterPublicKeysHex are the root master public keys (Ed25519) trusted to
// sign the server's submaster certificate. A chain verifies if any one of them
// signed it. Each is the authentication subkey of an OpenPGP key generated on
// a YubiKey; verify one with gpg --export-ssh-key <primary fingerprint>.
var masterPublicKeysHex = []string{
	// Original root, YubiKey 32493801. Trusted until the submaster cert it
	// signed expires on 2026-12-11.
	// Primary: 49C1CA77D17984E0D25C0994D626409AD567D479
	"6773cdfdfb7fc44f13f097449b715e7147a2d73f525d9f09a8d25229e458a2fb",
	// root-a, YubiKey 40127477.
	// Primary: B89594D5DD7B9213E5FC7DC27FC9430452C9F38D
	// Auth:    A53549AF5B5570F304D4342D702AEFFF07B512EF
	"73358e45a5c77b7f7236d26f5a1756011b522d277bb19ac4869d2e88952705cd",
	// root-b, YubiKey 40127498.
	// Primary: A980BA5DD0B3831A4038D22C744D413D801A1AFA
	// Auth:    B217F9743D6FD3EB21FF87D83752947C4AD9CC5E
	"4f9369b8a4a0fd9be67cd403e4ed92e0d45609772659be4a066c1a9c4eff43fe",
	// root-c, YubiKey 40127484.
	// Primary: 7F3CC680FF472FCF9A351CAF8204C38EAF10DA14
	// Auth:    59282CA469B7E8168952E07476352E58361B3A92
	"46d45bbc3280df763fcaf7a37055888eeefbb5781784c1f471f4f413d72b123f",
}

// masterPublicKeys decodes masterPublicKeysHex.
func masterPublicKeys() []ed25519.PublicKey {
	keys := make([]ed25519.PublicKey, 0, len(masterPublicKeysHex))
	for _, h := range masterPublicKeysHex {
		b, _ := hex.DecodeString(h)
		keys = append(keys, b)
	}
	return keys
}

const (
	licenseTypePerpetualFixed = "perpetual_fixed"
	licenseTypePerpetual      = "perpetual"
	licenseTypeExpiring       = "expiring"
)
