package latte

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/licenselatte/latte-go/internal/core/domain"
	"github.com/licenselatte/latte-go/internal/core/ports"
	"github.com/licenselatte/latte-go/internal/infra/storage"
	"github.com/licenselatte/latte-go/internal/infra/verify"
)

// spyRenewer counts Renew calls and records the highest number running at
// once. When block is set, each call waits on it after signalling entered.
// It answers with err, or with raw and chain when both are unset it fails as
// an unclassified error.
type spyRenewer struct {
	calls, running, maxRunning atomic.Int32
	entered                    chan struct{}
	block                      chan struct{}
	err                        error
	raw                        string
	chain                      *domain.CertChain
}

func (r *spyRenewer) Renew(context.Context, string, string, string) (string, *domain.CertChain, error) {
	r.calls.Add(1)
	n := r.running.Add(1)
	defer r.running.Add(-1)
	for {
		m := r.maxRunning.Load()
		if n <= m || r.maxRunning.CompareAndSwap(m, n) {
			break
		}
	}
	if r.entered != nil {
		r.entered <- struct{}{}
	}
	if r.block != nil {
		<-r.block
	}
	if r.err == nil && r.raw == "" {
		return "", nil, errors.New("offline")
	}
	return r.raw, r.chain, r.err
}

// waitEntered fails the test if no renewal reaches the renewer in time.
func waitEntered(t *testing.T, spy *spyRenewer) {
	t.Helper()
	select {
	case <-spy.entered:
	case <-time.After(2 * time.Second):
		close(spy.block)
		t.Fatal("renewer was never called")
	}
}

// cachedToken is an unverified token holding the activation licenseIssuedAgo
// builds, which is all holdsActivation reads.
func cachedToken(t *testing.T) string {
	t.Helper()
	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"aid": "act-1", "sub": "KEY1"}).SignedString([]byte("k"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func renewTestSDK(t *testing.T, r *spyRenewer) *SDK {
	t.Helper()
	store := storage.NewMemoryStorage()
	_ = store.SaveToken(cachedToken(t), nil)
	return &SDK{renewer: r, store: store, machineID: "machine-hash"}
}

func (s *SDK) renewalFailedForTest() bool {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.renewFailed
}

func licenseIssuedAgo(d time.Duration) *domain.License {
	return &domain.License{Key: "KEY1", ActivationID: "act-1", IssuedAt: time.Now().Add(-d)}
}

// attempt runs one renewal the way Check does and waits for it to finish.
func attempt(s *SDK, lic *domain.License) bool {
	if !s.shouldTryRenew(lic) {
		return false
	}
	s.silentRenew(lic)
	return true
}

func TestRenewFiresForOldToken(t *testing.T) {
	spy := &spyRenewer{}
	s := renewTestSDK(t, spy)
	lic := licenseIssuedAgo(2 * time.Hour)

	if !attempt(s, lic) {
		t.Fatal("a token older than 60 minutes must start a renewal")
	}
	if got := spy.calls.Load(); got != 1 {
		t.Fatalf("renewer calls = %d, want 1", got)
	}
	s.stateMu.Lock()
	inFlight := s.renewInFlight
	s.stateMu.Unlock()
	if inFlight {
		t.Fatal("renewInFlight still set after the renewal finished")
	}
}

func TestRenewSkipsFreshToken(t *testing.T) {
	spy := &spyRenewer{}
	s := renewTestSDK(t, spy)

	if attempt(s, licenseIssuedAgo(30*time.Minute)) {
		t.Fatal("a token younger than 60 minutes must not renew")
	}
	if got := spy.calls.Load(); got != 0 {
		t.Fatalf("renewer calls = %d, want 0", got)
	}
}

func TestRenewFiveMinuteFloor(t *testing.T) {
	spy := &spyRenewer{}
	s := renewTestSDK(t, spy)
	lic := licenseIssuedAgo(2 * time.Hour)

	attempt(s, lic)
	for i := 0; i < 3; i++ {
		if attempt(s, lic) {
			t.Fatal("a second attempt inside the 5-minute window must not start")
		}
	}
	if got := spy.calls.Load(); got != 1 {
		t.Fatalf("renewer calls inside the window = %d, want 1", got)
	}

	s.stateMu.Lock()
	s.lastRenewAttempt = time.Now().Add(-minRenewalTime - time.Second)
	s.stateMu.Unlock()
	if !attempt(s, lic) {
		t.Fatal("an attempt after the 5-minute window must start")
	}
	if got := spy.calls.Load(); got != 2 {
		t.Fatalf("renewer calls after the window = %d, want 2", got)
	}
}

func TestRenewNeverConcurrent(t *testing.T) {
	spy := &spyRenewer{entered: make(chan struct{}, 1), block: make(chan struct{})}
	s := renewTestSDK(t, spy)
	lic := licenseIssuedAgo(2 * time.Hour)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.shouldTryRenew(lic) {
				s.silentRenew(lic)
			}
		}()
	}
	waitEntered(t, spy)
	close(spy.block)
	wg.Wait()

	if got := spy.maxRunning.Load(); got != 1 {
		t.Fatalf("concurrent renewals = %d, want 1", got)
	}
	if got := spy.calls.Load(); got != 1 {
		t.Fatalf("renewer calls = %d, want 1", got)
	}
}

func TestShouldTryRenewDoesNotWaitOnRenewal(t *testing.T) {
	spy := &spyRenewer{entered: make(chan struct{}, 1), block: make(chan struct{})}
	s := renewTestSDK(t, spy)
	lic := licenseIssuedAgo(2 * time.Hour)

	if !s.shouldTryRenew(lic) {
		t.Fatal("first attempt must start")
	}
	done := make(chan struct{})
	go func() {
		s.silentRenew(lic)
		close(done)
	}()
	waitEntered(t, spy)

	returned := make(chan bool, 1)
	go func() { returned <- s.shouldTryRenew(lic) }()
	select {
	case started := <-returned:
		if started {
			t.Error("shouldTryRenew started a second renewal while one is in flight")
		}
	case <-time.After(2 * time.Second):
		t.Error("shouldTryRenew blocked behind an in-flight renewal")
	}

	close(spy.block)
	<-done
}

func TestRenewFailedFollowsTheOutcome(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		wantFlag  bool
		wantWiped bool
	}{
		{"transport failure sets it", fmt.Errorf("%w: dial tcp", ports.ErrNetworkError), true, false},
		{"server error clears it", errors.New("licenselatte: HTTP 503"), false, false},
		{"decode error clears it", errors.New("licenselatte: decode response: EOF"), false, false},
		{"inactive licence clears it and wipes the cache", ports.ErrLicenseInactiveOrExpired, false, true},
		{"unknown licence clears it and wipes the cache", ports.ErrLicenseNotFound, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := renewTestSDK(t, &spyRenewer{err: c.err})
			s.renewFailed = !c.wantFlag
			s.silentRenew(licenseIssuedAgo(2 * time.Hour))

			if got := s.renewalFailedForTest(); got != c.wantFlag {
				t.Errorf("renewFailed = %v, want %v", got, c.wantFlag)
			}
			raw, _, _ := s.store.LoadToken()
			if wiped := raw == ""; wiped != c.wantWiped {
				t.Errorf("cache wiped = %v, want %v", wiped, c.wantWiped)
			}
		})
	}
}

func TestRenewFailedIgnoresAStaleAttempt(t *testing.T) {
	s := renewTestSDK(t, &spyRenewer{err: ports.ErrNetworkError})
	stale := licenseIssuedAgo(2 * time.Hour)
	stale.ActivationID = "act-from-before-deactivate"

	s.silentRenew(stale)
	if s.renewalFailedForTest() {
		t.Fatal("an attempt whose activation is gone must not set the flag")
	}

	s.renewFailed = true
	s.renewer = &spyRenewer{err: errors.New("offline")}
	s.silentRenew(stale)
	if !s.renewalFailedForTest() {
		t.Fatal("an attempt whose activation is gone must not clear the flag either")
	}
}

// fakeMachines releases any activation.
type fakeMachines struct{ ports.MachineManager }

func (fakeMachines) Deactivate(context.Context, string, string, string) (bool, *time.Time, error) {
	return true, nil, nil
}

// fakeActivator answers every activation with the spy's token.
type fakeActivator struct {
	ports.Activator
	spy *spyRenewer
}

func (a fakeActivator) Activate(context.Context, string, string) (string, *domain.CertChain, error) {
	return a.spy.raw, a.spy.chain, nil
}

func TestDeactivateResetsRenewFailed(t *testing.T) {
	s := renewTestSDK(t, &spyRenewer{})
	s.machines = fakeMachines{}
	s.renewFailed = true

	if _, err := s.Deactivate(); err != nil {
		t.Fatal(err)
	}
	if s.renewalFailedForTest() {
		t.Fatal("Deactivate must reset renewFailed")
	}
}

// renewFixture loads the accepted vector that is older than 60 minutes and
// returns an SDK whose clock, root key and machine are the vector's, holding
// its token in the cache.
func renewFixture(t *testing.T, r *spyRenewer) (*SDK, *domain.License) {
	t.Helper()
	for _, f := range loadFixtures(t) {
		if f.Name != "valid_in_grace_period" {
			continue
		}
		masterPub, _ := hex.DecodeString(f.MasterPublicKeyHex)
		chain := &domain.CertChain{Submaster: f.Chain.Submaster, Project: f.Chain.Project, Daily: f.Chain.Daily}
		lic, err := verify.VerifyActivationAt(masterPub, f.Token, chain, f.Now)
		if err != nil {
			t.Fatal(err)
		}
		store := storage.NewMemoryStorage()
		_ = store.SaveToken(f.Token, chain)
		r.raw, r.chain = f.Token, chain
		now := f.Now
		return &SDK{
			renewer:    r,
			store:      store,
			machineID:  f.MachineID,
			masterPubs: []ed25519.PublicKey{masterPub},
			now:        func() time.Time { return now },
		}, lic
	}
	t.Fatal("valid_in_grace_period vector missing")
	return nil, nil
}

func TestSuccessfulRenewalClearsRenewFailed(t *testing.T) {
	s, lic := renewFixture(t, &spyRenewer{})
	s.renewFailed = true

	s.silentRenew(lic)

	if s.renewalFailedForTest() {
		t.Fatal("a renewal that saved a verified token must clear renewFailed")
	}
}

func TestUnverifiableRenewedTokenKeepsTheCacheAndClearsRenewFailed(t *testing.T) {
	spy := &spyRenewer{}
	s, lic := renewFixture(t, spy)
	before, _, _ := s.store.LoadToken()
	spy.raw = "not-a-token"
	s.renewFailed = true

	s.silentRenew(lic)

	if after, _, _ := s.store.LoadToken(); after != before {
		t.Fatal("a renewed token that fails verification must not replace the cache")
	}
	if s.renewalFailedForTest() {
		t.Fatal("a renewed token that fails verification is not a connectivity failure")
	}
}

func TestNetworkActivationResetsRenewFailed(t *testing.T) {
	spy := &spyRenewer{}
	s, _ := renewFixture(t, spy)
	s.store = storage.NewFileStorage(filepath.Join(t.TempDir(), "cache.latte"))
	s.activator = fakeActivator{spy: spy}
	s.renewFailed = true

	if _, err := s.Activate("KEY1"); err != nil {
		t.Fatal(err)
	}
	if s.renewalFailedForTest() {
		t.Fatal("a fresh activation must reset renewFailed")
	}
}

func TestInGracePeriodNeedsAFailedRenewal(t *testing.T) {
	lic := &domain.License{IssuedAt: time.Unix(0, 0), GracePeriod: 72 * time.Hour}
	at := func(age time.Duration) time.Time { return lic.IssuedAt.Add(age) }
	cases := []struct {
		age    time.Duration
		failed bool
		want   bool
	}{
		{2 * time.Hour, false, false},
		{2 * time.Hour, true, true},
		{30 * time.Minute, true, false},
		{60 * time.Minute, true, false},
		{72 * time.Hour, true, false},
	}
	for _, c := range cases {
		if got := domainToPublic(lic, at(c.age), c.failed).InGracePeriod; got != c.want {
			t.Errorf("age %s renewalFailed=%v: InGracePeriod = %v, want %v", c.age, c.failed, got, c.want)
		}
	}
}
