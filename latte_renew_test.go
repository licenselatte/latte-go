package latte

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/licenselatte/latte-go/internal/core/domain"
)

// spyRenewer counts Renew calls and records the highest number running at
// once. When block is set, each call waits on it after signalling entered.
type spyRenewer struct {
	calls, running, maxRunning atomic.Int32
	entered                    chan struct{}
	block                      chan struct{}
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
	return "", nil, errors.New("offline")
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

func renewTestSDK(r *spyRenewer) *SDK {
	return &SDK{renewer: r, machineID: "machine-hash"}
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
	s := renewTestSDK(spy)
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
	s := renewTestSDK(spy)

	if attempt(s, licenseIssuedAgo(30*time.Minute)) {
		t.Fatal("a token younger than 60 minutes must not renew")
	}
	if got := spy.calls.Load(); got != 0 {
		t.Fatalf("renewer calls = %d, want 0", got)
	}
}

func TestRenewFiveMinuteFloor(t *testing.T) {
	spy := &spyRenewer{}
	s := renewTestSDK(spy)
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
	s := renewTestSDK(spy)
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
	s := renewTestSDK(spy)
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
