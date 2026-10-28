package latte

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/licenselatte/latte-go/internal/core/domain"
	"github.com/licenselatte/latte-go/internal/core/ports"
	"github.com/licenselatte/latte-go/internal/infra/storage"
)

// lapsedNow is the pinned clock. It tracks the wall clock because Check also
// asks License.IsValid, which reads time.Now.
var lapsedNow = time.Now().UTC().Truncate(time.Second)

const lapsedMachine = "lapsed-machine"

func lapsedKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func lapsedSign(t *testing.T, priv ed25519.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// lapsedIssuer mints cert chains and activation tokens under one root key.
type lapsedIssuer struct {
	t         *testing.T
	masterPub ed25519.PublicKey
	masterKey ed25519.PrivateKey
}

func newLapsedIssuer(t *testing.T) *lapsedIssuer {
	pub, priv := lapsedKey(t)
	return &lapsedIssuer{t: t, masterPub: pub, masterKey: priv}
}

// token mints an activation token issued at iat with a 72h offline window,
// signed through a chain whose project cert ends at projectExp and whose
// daily cert covers the day of iat.
func (i *lapsedIssuer) token(iat, projectExp time.Time, machine string) (string, *domain.CertChain) {
	t := i.t
	subPub, subKey := lapsedKey(t)
	projPub, projKey := lapsedKey(t)
	dayPub, dayKey := lapsedKey(t)
	day := iat.Truncate(24 * time.Hour)
	chain := &domain.CertChain{
		Submaster: lapsedSign(t, i.masterKey, jwt.MapClaims{
			"iss": "licenselatte", "iat": day.AddDate(-1, 0, 0).Unix(), "exp": day.AddDate(1, 0, 0).Unix(), "spk": hex.EncodeToString(subPub),
		}),
		Project: lapsedSign(t, subKey, jwt.MapClaims{
			"iss": "licenselatte", "iat": day.AddDate(0, -1, 0).Unix(), "exp": projectExp.Unix(), "ppk": hex.EncodeToString(projPub), "pid": "proj-1",
		}),
		Daily: lapsedSign(t, projKey, jwt.MapClaims{
			"iss": "licenselatte", "iat": day.Unix(), "exp": day.Add(24*time.Hour + 5*time.Minute).Unix(), "dpk": hex.EncodeToString(dayPub),
		}),
	}
	raw := lapsedSign(t, dayKey, jwt.MapClaims{
		"iss": "licenselatte", "sub": "KEY1", "aid": "act-1", "pid": "proj-1", "mid": machine, "ltype": "perpetual",
		"iat": iat.Unix(), "exp": iat.AddDate(1, 0, 0).Unix(), "grc": int64(72 * 3600),
	})
	return raw, chain
}

// lapsedSDK holds a cached token minted by issuer; the renewer answers with a
// fresh token valid at lapsedNow.
func lapsedSDK(t *testing.T, issuer *lapsedIssuer, raw string, chain *domain.CertChain) (*SDK, *spyRenewer) {
	t.Helper()
	spy := &spyRenewer{}
	spy.raw, spy.chain = issuer.token(lapsedNow, lapsedNow.AddDate(0, 3, 0), lapsedMachine)
	store := storage.NewMemoryStorage()
	_ = store.SaveToken(raw, chain)
	return &SDK{
		renewer:    spy,
		store:      store,
		machineID:  lapsedMachine,
		masterPubs: []ed25519.PublicKey{issuer.masterPub},
		now:        func() time.Time { return lapsedNow },
	}, spy
}

// waitRenewIdle blocks until no renewal is running; Check marks one in flight
// before it returns.
func waitRenewIdle(t *testing.T, s *SDK) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		s.stateMu.Lock()
		busy := s.renewInFlight
		s.stateMu.Unlock()
		if !busy {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("renewal never finished")
		}
		time.Sleep(time.Millisecond)
	}
}

func checkNotActivated(t *testing.T, s *SDK) {
	t.Helper()
	if _, err := s.Check(); !errors.Is(err, ErrNotActivated) {
		t.Fatalf("Check error = %v, want ErrNotActivated", err)
	}
}

func TestCheckRenewsATokenPastItsGraceDeadline(t *testing.T) {
	issuer := newLapsedIssuer(t)
	raw, chain := issuer.token(lapsedNow.Add(-10*24*time.Hour), lapsedNow.AddDate(0, 3, 0), lapsedMachine)
	s, spy := lapsedSDK(t, issuer, raw, chain)

	spy.block = make(chan struct{})
	spy.entered = make(chan struct{}, 1)
	checkNotActivated(t, s)
	waitEntered(t, spy)
	checkNotActivated(t, s)
	close(spy.block)
	waitRenewIdle(t, s)
	if got := spy.calls.Load(); got != 1 {
		t.Fatalf("renewer calls = %d, want 1", got)
	}

	lic, err := s.Check()
	if err != nil {
		t.Fatalf("Check after the renewal: %v", err)
	}
	if lic.Key != "KEY1" || lic.InGracePeriod {
		t.Fatalf("license after the renewal = %+v", lic)
	}
	waitRenewIdle(t, s)
	if got := spy.calls.Load(); got != 1 {
		t.Fatalf("renewer calls after recovery = %d, want 1", got)
	}
}

func TestCheckRenewsATokenWhoseCertChainHasExpired(t *testing.T) {
	issuer := newLapsedIssuer(t)
	raw, chain := issuer.token(lapsedNow.Add(-2*time.Hour), lapsedNow.Add(-24*time.Hour), lapsedMachine)
	s, spy := lapsedSDK(t, issuer, raw, chain)

	checkNotActivated(t, s)
	waitRenewIdle(t, s)
	if got := spy.calls.Load(); got != 1 {
		t.Fatalf("renewer calls = %d, want 1", got)
	}
	if _, err := s.Check(); err != nil {
		t.Fatalf("Check after the renewal: %v", err)
	}
}

func TestCheckDoesNotRenewATokenThatDoesNotVerify(t *testing.T) {
	issuer := newLapsedIssuer(t)
	other := newLapsedIssuer(t)
	old := lapsedNow.Add(-10 * 24 * time.Hour)
	raw, chain := issuer.token(old, lapsedNow.AddDate(0, 3, 0), lapsedMachine)
	wrongMachine, wrongMachineChain := issuer.token(old, lapsedNow.AddDate(0, 3, 0), "another-machine")
	i := strings.LastIndex(raw, ".") + 1
	flipped := raw[:i] + string(map[bool]byte{true: 'B', false: 'A'}[raw[i] == 'A']) + raw[i+1:]

	cases := []struct {
		name string
		raw  string
		pub  ed25519.PublicKey
		ch   *domain.CertChain
	}{
		{"tampered signature", flipped, issuer.masterPub, chain},
		{"unknown root key", raw, other.masterPub, chain},
		{"another machine", wrongMachine, issuer.masterPub, wrongMachineChain},
		{"garbage", "not-a-token", issuer.masterPub, chain},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, spy := lapsedSDK(t, issuer, c.raw, c.ch)
			s.masterPubs = []ed25519.PublicKey{c.pub}

			checkNotActivated(t, s)
			waitRenewIdle(t, s)
			if got := spy.calls.Load(); got != 0 {
				t.Fatalf("renewer calls = %d, want 0", got)
			}
		})
	}
}

func TestLapsedRenewalOutcome(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		wantFlag  bool
		wantWiped bool
	}{
		{"rejection wipes the cache", ports.ErrLicenseNotFound, false, true},
		{"inactive licence wipes the cache", ports.ErrLicenseInactiveOrExpired, false, true},
		{"network failure keeps the cache and sets the flag", fmt.Errorf("%w: dial tcp", ports.ErrNetworkError), true, false},
		{"server error keeps the cache", errors.New("licenselatte: HTTP 503"), false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			issuer := newLapsedIssuer(t)
			raw, chain := issuer.token(lapsedNow.Add(-10*24*time.Hour), lapsedNow.AddDate(0, 3, 0), lapsedMachine)
			s, spy := lapsedSDK(t, issuer, raw, chain)
			spy.raw, spy.err = "", c.err

			checkNotActivated(t, s)
			waitRenewIdle(t, s)

			if got := s.renewalFailedForTest(); got != c.wantFlag {
				t.Errorf("renewFailed = %v, want %v", got, c.wantFlag)
			}
			cached, _, _ := s.store.LoadToken()
			if wiped := cached == ""; wiped != c.wantWiped {
				t.Errorf("cache wiped = %v, want %v", wiped, c.wantWiped)
			}
		})
	}
}
