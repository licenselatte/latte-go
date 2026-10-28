package storage

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/licenselatte/latte-go/internal/core/domain"
)

func TestSaveTokenConcurrentWithLoadToken(t *testing.T) {
	sizes := []int{8, 200_000, 64, 500_000}

	for round := 0; round < 30; round++ {
		dir := t.TempDir()
		fs := NewFileStorage(filepath.Join(dir, "cache"))

		var saved atomic.Bool
		var writers, readers sync.WaitGroup
		done := make(chan struct{})
		failures := make(chan string, 64)

		for i, size := range sizes {
			writers.Add(1)
			go func(c string, size int) {
				defer writers.Done()
				token := strings.Repeat(c, size)
				chain := &domain.CertChain{Submaster: c, Project: c, Daily: c}
				for j := 0; j < 10; j++ {
					if err := fs.SaveToken(token, chain); err != nil {
						failures <- "save: " + err.Error()
						return
					}
					saved.Store(true)
				}
			}(string(rune('a'+i)), size)
		}

		for r := 0; r < 3; r++ {
			readers.Add(1)
			go func() {
				defer readers.Done()
				for {
					select {
					case <-done:
						return
					default:
					}
					wasSaved := saved.Load()
					token, chain, err := fs.LoadToken()
					if err != nil {
						if wasSaved || !os.IsNotExist(err) {
							failures <- "load after first save: " + err.Error()
							return
						}
						continue
					}
					c := token[:1]
					if token != strings.Repeat(c, len(token)) || chain.Daily != c || chain.Project != c || chain.Submaster != c {
						failures <- "load returned a mixed record"
						return
					}
				}
			}()
		}

		writers.Wait()
		close(done)
		readers.Wait()
		close(failures)
		for msg := range failures {
			t.Fatalf("round %d: %s", round, msg)
		}

		tmps, _ := filepath.Glob(filepath.Join(dir, "*.tmp"))
		if len(tmps) != 0 {
			t.Fatalf("round %d: leftover temp files: %v", round, tmps)
		}
	}
}

func TestSaveTokenWipeKeepsCacheLoadable(t *testing.T) {
	fs := NewFileStorage(filepath.Join(t.TempDir(), "cache"))
	if err := fs.SaveToken("tok", &domain.CertChain{Daily: "d"}); err != nil {
		t.Fatal(err)
	}
	if err := fs.SaveToken("", nil); err != nil {
		t.Fatal(err)
	}
	token, chain, err := fs.LoadToken()
	if err != nil || token != "" || chain.Daily != "" {
		t.Fatalf("got %q %+v %v", token, chain, err)
	}
}
