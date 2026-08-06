# latte-go

[![CI](https://github.com/licenselatte/latte-go/actions/workflows/ci.yml/badge.svg)](https://github.com/licenselatte/latte-go/actions/workflows/ci.yml)

Official Go SDK for [LicenseLatte](https://licenselatte.com), the software licensing platform.

Embed license enforcement directly into your Go application in a few lines of code. The SDK handles activation, offline grace periods, background token renewal, and local token caching transparently.

---

## Table of contents

- [Installation](#installation)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [API reference](#api-reference)
  - [New](#new)
  - [Activate / ActivateWithContext](#activate--activatewithcontext)
  - [Check](#check)
- [The License struct](#the-license-struct)
- [License types](#license-types)
- [Offline grace period](#offline-grace-period)
- [Error handling](#error-handling)
- [Token storage](#token-storage)
- [Background renewal](#background-renewal)
- [Custom metadata](#custom-metadata)
- [Environments](#environments)
- [Testing](#testing)

---

## Installation

```sh
go get github.com/licenselatte/latte-go
```

Requires Go 1.21+.

---

## Quick start

```go
package main

import (
    "fmt"
    "log"

    latte "github.com/licenselatte/latte-go"
)

func main() {
    // 1. Create one SDK instance per application (process lifetime).
    //    AppID is the project key from the LicenseLatte dashboard.
    sdk, err := latte.New(&latte.Config{
        AppID: "pk_live_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    })
    if err != nil {
        log.Fatalf("failed to initialize SDK: %v", err)
    }

    // 2. Activate the license key entered by the user.
    //    Returns immediately from cache if already activated on this machine.
    lic, err := sdk.Activate("XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX")
    if err != nil {
        switch err {
        case latte.ErrInvalidKey:
            log.Fatal("that doesn't look like a valid license key")
        case latte.ErrLicenseExpired:
            log.Fatal("your license has expired, please renew")
        case latte.ErrSeatLimit:
            log.Fatal("all activation slots are in use")
        default:
            log.Fatalf("activation error: %v", err)
        }
    }

    fmt.Printf("activated, expires %s\n", lic.ExpiresAt.Format("2006-01-02"))

    // 3. On each subsequent startup, check the locally-stored token.
    //    No network call; works offline within the grace period.
    lic, err = sdk.Check()
    if err != nil {
        if err == latte.ErrLicenseExpired {
            log.Fatal("license expired, please reconnect to renew")
        }
        // ErrNotActivated: call Activate first.
        log.Fatalf("check failed: %v", err)
    }

    if lic.InGracePeriod {
        fmt.Println("warning: offline too long, please reconnect soon")
    }

    // ... run your application
}
```

---

## Configuration

```go
type Config struct {
    // AppID is the project key shown in the LicenseLatte dashboard.
    // Format: pk_{env}_{32-char key}
    // Environments: live, test
    AppID string
}
```

The `AppID` encodes the environment and is validated on `New`. A checksum is embedded in the key itself, a typo returns `ErrInvalidAppID` or `ErrInvalidAppIDChecksum` at startup, not at runtime.

---

## API reference

### New

```go
func New(config *Config) (*SDK, error)
```

Creates and returns a new SDK instance. Call once at application startup and reuse the returned `*SDK` for the lifetime of the process.

`New` will error if:
- `AppID` is malformed or has an invalid checksum (`ErrInvalidAppID`, `ErrInvalidAppIDChecksum`)
- The token storage directory cannot be created (`ErrStorageInitFailed`)
- The machine fingerprint cannot be read (`ErrMachineIDFailed`)


### Activate / ActivateWithContext

```go
func (s *SDK) Activate(key string) (*License, error)
func (s *SDK) ActivateWithContext(ctx context.Context, key string) (*License, error)
```

Validates the license key and activates this machine.

**Fast path (cache hit):** if a valid token is already stored locally the call returns in microseconds without a network request. A background goroutine silently renews the token in the background so the cache stays fresh.

**Slow path (cache miss or expired token):** the SDK calls the LicenseLatte API to activate the machine and store the resulting token.

The `key` argument accepts any reasonable user input: hyphens, spaces, lowercase, and the ambiguous characters `O/0`, `I/L/1` are all normalised automatically.

### Check

```go
func (s *SDK) Check() (*License, error)
```

Validates the locally-stored token without making a network call. Use this for startup checks and periodic in-process gates (e.g. before allowing a premium feature).

Returns `ErrNotActivated` if `Activate` has never been called on this machine.
Returns `ErrLicenseExpired` if the token's grace period has elapsed.

---

## The License struct

```go
type License struct {
    Key           string            // raw license key (no hyphens)
    ActivationID  string            // server UUID for this machine's activation slot
    ProjectID     string            // UUID of the owning project
    IssuedAt      time.Time         // when the server last issued / renewed this token
    ExpiresAt     time.Time         // hard expiry of the license (year 2099 for perpetual_fixed)
    MachineIDHash string            // machine fingerprint 
    GracePeriod   time.Duration     // offline tolerance window from IssuedAt
    InGracePeriod bool              // true → device has been offline a long time; reconnect soon
    LicenseType   string            // "perpetual_fixed" | "perpetual" | "expiring"
    Claims        map[string]any    // full JWT payload (includes custom metadata fields)
}
```

`InGracePeriod` is `true` once the device has been offline longer than `maxRenewalTime` (60 minutes) but has not yet exhausted the full `GracePeriod`. Surface this to the user as a "please reconnect" warning.

---

## License types

| Type | Expiry | Renewal | Revocable |
|---|---|---|---|
| `perpetual_fixed` | Never (year 2099) | Never needed | No |
| `perpetual` | Never | Periodic (background) | Yes |
| `expiring` | Set by policy | Periodic (background) | Yes |

**`perpetual_fixed`** tokens are irrevocable one-time activations. The server signs a token that expires in 2099 and the SDK never contacts the API again after the first activation. There is no grace period.

**`perpetual`** and **`expiring`** licenses use a rolling-renewal model. The SDK renews the cached token in the background every 5–60 minutes. The grace period gives the device a buffer to work offline if the renewal fails.

---

## Offline grace period

The grace period (`GracePeriod`) is an offline tolerance window measured **from the last token issuance** (`IssuedAt`), not from the expiry date. While `now ≤ IssuedAt + GracePeriod`, the device may operate without a network connection.

```
IssuedAt ──────────────────────────────────> ExpiresAt
              |                   |
              └── GracePeriod ────┘
                  ^ offline window
```

Two special cases result in an expired token:

1. **Collision**: `IssuedAt + GracePeriod > ExpiresAt`: the grace window extends past the license hard expiry. The SDK treats this as expired.
2. **Offline too long**: `now > IssuedAt + GracePeriod`: the device has been offline longer than the grace window allows. The user must reconnect to receive a fresh token.

The `InGracePeriod` field on `*License` lets you show a "please reconnect" banner before the deadline is reached.

---

## Error handling

```go
// Activation / Check errors
var (
    ErrInvalidKey      = errors.New("licenselatte: invalid license key")
    ErrLicenseExpired  = errors.New("licenselatte: license expired")
    ErrNotActivated    = errors.New("licenselatte: not activated on this machine")
    ErrSeatLimit       = errors.New("licenselatte: activation seat limit reached")
    ErrLicenseNotFound = errors.New("licenselatte: license not found")
    ErrInvalidProjectKey = errors.New("licenselatte: invalid project key")
)

// SDK initialisation errors (returned by New)
var (
    ErrInvalidAppID          = errors.New("licenselatte: invalid AppID")
    ErrUnknownEnvironment    = errors.New("licenselatte: unknown environment")
    ErrInvalidAppIDKeySegment = errors.New("licenselatte: invalid app id key segment")
    ErrInvalidAppIDChecksum  = errors.New("licenselatte: invalid app id checksum")
    ErrStorageInitFailed     = errors.New("licenselatte: cannot initialize storage")
    ErrMachineIDFailed       = errors.New("licenselatte: cannot determine machine ID")
)
```

All errors are sentinel values, use `errors.Is` for comparison:

```go
lic, err := sdk.Activate(key)
if errors.Is(err, latte.ErrSeatLimit) {
    // inform the user to deactivate another machine
}
```

---

## Token storage

Tokens are stored as plain JWT strings in a file at:

| OS | Path |
|---|---|
| macOS | `~/Library/Application Support/LicenseLatte/{appkey}.latte` |
| Linux | `~/.config/LicenseLatte/{appkey}.latte` |
| Windows | `%AppData%\LicenseLatte\{appkey}.latte` |

If the OS config directory is unavailable the SDK falls back to `.licenselatte/{appkey}.latte` relative to the working directory.

Each project has its own file (keyed by the 32-char project key segment), so multiple products installed on the same machine don't interfere with each other.

---

## Background renewal

When `Activate` or `Check` returns a valid cached token, the SDK fires a background goroutine that calls `POST /v1/renew` and overwrites the stored token with the fresh one.

Renewal happens between 5 and 60 minutes after the last issuance (randomised to spread server load). Renewal errors are silently ignored, the existing token remains valid until its grace period elapses.

`perpetual_fixed` licenses skip renewal entirely: the token is permanent and the server is never contacted after the initial activation.

---

## Custom metadata

When issuing a license from the dashboard you can attach arbitrary metadata (e.g. customer name, plan tier, feature flags). These values are embedded in the JWT and exposed via `License.Claims`:

```go
lic, _ := sdk.Activate(key)

if tier, ok := lic.Claims["tier"].(string); ok {
    fmt.Println("plan tier:", tier)
}
```

Claims are signed by the server, they cannot be tampered with by the client.

---

## Environments

The `AppID` prefix determines which API endpoint the SDK talks to:

| Prefix | Endpoint | Purpose |
|---|---|---|
| `pk_live_` | `https://api.licenselatte.com` | Production |
| `pk_test_` | `https://test.api.licenselatte.com` | Sandbox / CI |

---

## Testing

The SDK's core validation logic is verified against a shared set of test vectors used by every LicenseLatte SDK, defined in `SPEC.md` and generated by `latte-testvectors/generator`. These vectors live in the `testdata` git submodule.

If the submodule isn't populated yet, initialize it first:

```sh
git submodule update --init
```

Then run the fixture tests:

```sh
go test -run TestFixtures -v .
```

CI runs on every push and pull request to `main` (`.github/workflows/ci.yml`), with separate jobs for tests, `go vet`, `gofmt`, and `golangci-lint`.

---

## License

MIT, see [LICENSE](LICENSE).
