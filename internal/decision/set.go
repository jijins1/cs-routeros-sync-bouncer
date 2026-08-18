package decision

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// OriginFilter selects which decision origins this bouncer enforces.
//
// Exclude is the practical lever for the memory problem: dropping one oversized
// blocklist wholesale is usually better than letting the cap trim it
// arbitrarily.
type OriginFilter struct {
	Include []string // when non-empty, only these origins are accepted
	Exclude []string // always rejected, and takes precedence over Include
}

// Allows reports whether decisions from origin should be enforced.
func (f OriginFilter) Allows(origin string) bool {
	for _, e := range f.Exclude {
		if e == origin {
			return false
		}
	}

	if len(f.Include) == 0 {
		return true
	}

	for _, i := range f.Include {
		if i == origin {
			return true
		}
	}
	return false
}

// bucket is every decision currently covering one address.
//
// CrowdSec issues one decision per scenario, so a single address can be the
// subject of several at once. The router only ever needs one entry for it, but
// that entry must survive until the last of those decisions is gone - hence
// the set of sources rather than a single value.
type bucket struct {
	sources map[int64]Decision
}

// resolve collapses the sources into the single entry the router should hold,
// and reports whether any source is still live at now.
//
// Expiry is the longest of the survivors and origin is the best-ranked one, so
// an address stays blocked as long as anything justifies it and is judged by
// the strongest reason it is blocked.
func (b *bucket) resolve(now time.Time) (Decision, bool) {
	var (
		best  Decision
		found bool
	)
	for _, d := range b.sources {
		if d.IsExpired(now) {
			continue
		}
		if !found {
			best, found = d, true
			continue
		}
		if d.ExpiresAt.After(best.ExpiresAt) {
			best.ExpiresAt = d.ExpiresAt
		}
		if originRank(d.Origin) < originRank(best.Origin) {
			best.Origin = d.Origin
		}
	}
	return best, found
}

// Set is the desired state: every address that should currently be on the
// router, keyed by canonical address so duplicates cannot exist by
// construction, and reference-counted by decision so an address is only
// released once nothing covers it any more.
//
// Set is safe for concurrent use; the stream consumer writes to it while the
// reconciler reads snapshots from it.
type Set struct {
	mu      sync.RWMutex
	buckets map[string]*bucket // canonical address -> covering decisions
	byID    map[int64]string   // decision id -> canonical address
	max     int                // 0 means unlimited
	filter  OriginFilter
}

// NewSet returns an empty Set. max caps how many entries a snapshot will ever
// yield, across both address families; 0 disables the cap.
func NewSet(max int, filter OriginFilter) *Set {
	return &Set{
		buckets: make(map[string]*bucket),
		byID:    make(map[int64]string),
		max:     max,
		filter:  filter,
	}
}

// Upsert records that d justifies blocking d.Key, reporting whether the set
// changed. Re-sending the same decision id is idempotent.
func (s *Set) Upsert(d Decision) bool {
	if !s.filter.Allows(d.Origin) {
		return false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.buckets[d.Key]
	if !ok {
		b = &bucket{sources: make(map[int64]Decision, 1)}
		s.buckets[d.Key] = b
	}

	previous, existed := b.sources[d.ID]
	b.sources[d.ID] = d
	s.byID[d.ID] = d.Key

	return !existed || previous != d
}

// Forget drops one decision, reporting whether it was known.
//
// The address it covered stays blocked if any other decision still applies to
// it. This is what makes an expiring scenario ban safe to process: unbanning
// on the first delete would lift a block that another scenario still wants.
func (s *Set) Forget(id int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	key, ok := s.byID[id]
	if !ok {
		return false
	}
	delete(s.byID, id)

	b, ok := s.buckets[key]
	if !ok {
		return true
	}

	delete(b.sources, id)
	if len(b.sources) == 0 {
		delete(s.buckets, key)
	}
	return true
}

// Delete removes an address and every decision covering it, reporting whether
// it was present. key must already be canonical.
func (s *Set) Delete(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.buckets[key]
	if !ok {
		return false
	}
	for id := range b.sources {
		delete(s.byID, id)
	}
	delete(s.buckets, key)
	return true
}

// Len returns the number of distinct addresses held, before expiry or capping.
func (s *Set) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.buckets)
}

// Snapshot returns the decisions that should be on the router as of now:
// addresses with no live decision dropped, ordered by priority, and trimmed to
// the cap.
//
// The cap is applied here rather than on insertion so that priority is judged
// against the whole live set. Trimming at insert time would let whichever
// decisions happened to arrive first squat the budget and lock out the local
// scenarios that matter most.
func (s *Set) Snapshot(now time.Time) []Decision {
	s.mu.RLock()
	out := make([]Decision, 0, len(s.buckets))
	for _, b := range s.buckets {
		if d, live := b.resolve(now); live {
			out = append(out, d)
		}
	}
	s.mu.RUnlock()

	sort.Slice(out, func(i, j int) bool {
		return lessPriority(out[i], out[j])
	})

	if s.max > 0 && len(out) > s.max {
		out = out[:s.max]
	}
	return out
}

// SnapshotByFamily is Snapshot split into the IPv4 and IPv6 address-lists.
//
// The cap applies to the combined result, since both lists consume the same
// router memory.
func (s *Set) SnapshotByFamily(now time.Time) (v4, v6 []Decision) {
	for _, d := range s.Snapshot(now) {
		if d.Family == IPv6 {
			v6 = append(v6, d)
		} else {
			v4 = append(v4, d)
		}
	}
	return v4, v6
}

// lessPriority orders decisions best-first, so that truncating the tail drops
// the most expendable entries.
func lessPriority(a, b Decision) bool {
	if ra, rb := originRank(a.Origin), originRank(b.Origin); ra != rb {
		return ra < rb
	}

	// Prefer the longer-lived ban: a decision about to expire buys little.
	if !a.ExpiresAt.Equal(b.ExpiresAt) {
		return a.ExpiresAt.After(b.ExpiresAt)
	}

	// Final tie-break keeps snapshots stable between passes, so the reconciler
	// does not compute a delta out of nothing.
	return a.Key < b.Key
}

// originRank scores origins best-first for capping purposes.
//
// Locally observed attacks and manual bans are the ones worth the router's
// memory; community blocklists are broad but speculative, and rank below them.
func originRank(origin string) int {
	switch {
	case origin == "crowdsec", origin == "cscli":
		return 0
	case strings.HasPrefix(origin, "lists:"):
		return 1
	case origin == "CAPI", origin == "capi":
		return 2
	default:
		return 3
	}
}
