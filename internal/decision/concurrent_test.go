package decision

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// The stream consumer writes to the Set while the reconciler reads snapshots
// from it. This exercises that overlap; run with -race to make it meaningful.
func TestSetConcurrentAccess(t *testing.T) {
	s := NewSet(500, OriginFilter{})

	const writers = 8
	const perWriter = 500

	var wg sync.WaitGroup

	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				id := int64(w*perWriter + i)
				d := Decision{
					ID:        id,
					Key:       fmt.Sprintf("10.%d.%d.%d", w, i>>8, i&0xff),
					Family:    IPv4,
					Origin:    "crowdsec",
					ExpiresAt: base.Add(time.Hour),
				}
				s.Upsert(d)
				if i%3 == 0 {
					s.Forget(id)
				}
			}
		}(w)
	}

	// Readers run throughout, mirroring the reconciler's periodic passes.
	done := make(chan struct{})
	var readers sync.WaitGroup
	for r := 0; r < 4; r++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				if got := s.Snapshot(base); len(got) > 500 {
					t.Errorf("snapshot exceeded the cap: %d entries", len(got))
					return
				}
				s.SnapshotByFamily(base)
				s.Len()
			}
		}()
	}

	wg.Wait()
	close(done)
	readers.Wait()

	// Two thirds of the writes survive their Forget; the cap bounds the rest.
	if got := len(s.Snapshot(base)); got != 500 {
		t.Errorf("final snapshot has %d entries, want the cap of 500", got)
	}
}
