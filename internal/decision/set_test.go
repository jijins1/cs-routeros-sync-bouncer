package decision

import (
	"fmt"
	"testing"
	"time"
)

var base = time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)

var nextTestID int64

// mk builds a decision with a fresh id, mirroring CrowdSec issuing one
// decision per scenario. Tests that care about a specific id use src instead.
func mk(key, origin string, ttl time.Duration) Decision {
	k, fam, err := Canonicalize(key)
	if err != nil {
		panic(err)
	}
	nextTestID++
	return Decision{ID: nextTestID, Key: k, Family: fam, Origin: origin, ExpiresAt: base.Add(ttl)}
}

func keysOf(ds []Decision) []string {
	out := make([]string, len(ds))
	for i, d := range ds {
		out[i] = d.Key
	}
	return out
}

func TestSetDeduplicates(t *testing.T) {
	// The core of the OOM bug: the same IP arriving from several scenarios must
	// collapse into exactly one address-list entry.
	s := NewSet(0, OriginFilter{})
	s.Upsert(mk("1.2.3.4", "crowdsec", time.Hour))
	s.Upsert(mk("1.2.3.4", "crowdsec", time.Hour))
	s.Upsert(mk("1.2.3.4", "CAPI", time.Hour))

	got := s.Snapshot(base)
	if len(got) != 1 {
		t.Fatalf("Snapshot() returned %d entries (%v), want 1", len(got), keysOf(got))
	}
}

func TestSetDeduplicatesAcrossEquivalentForms(t *testing.T) {
	// 1.2.3.4 and 1.2.3.4/32 are the same router entry.
	s := NewSet(0, OriginFilter{})
	s.Upsert(mk("1.2.3.4", "crowdsec", time.Hour))
	s.Upsert(mk("1.2.3.4/32", "crowdsec", time.Hour))
	s.Upsert(mk("2001:db8::1", "crowdsec", time.Hour))
	s.Upsert(mk("2001:DB8::1/128", "crowdsec", time.Hour))

	got := s.Snapshot(base)
	if len(got) != 2 {
		t.Fatalf("Snapshot() returned %d entries (%v), want 2", len(got), keysOf(got))
	}
}

func TestSetKeepsLongestExpiry(t *testing.T) {
	// Re-banning an IP for a shorter time must not shorten an existing longer ban.
	s := NewSet(0, OriginFilter{})
	s.Upsert(mk("1.2.3.4", "crowdsec", 4*time.Hour))
	s.Upsert(mk("1.2.3.4", "crowdsec", time.Hour))

	got := s.Snapshot(base)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	if want := base.Add(4 * time.Hour); !got[0].ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v (longer ban must win)", got[0].ExpiresAt, want)
	}
}

func TestSetUpsertExtendsExpiry(t *testing.T) {
	s := NewSet(0, OriginFilter{})
	s.Upsert(mk("1.2.3.4", "crowdsec", time.Hour))
	s.Upsert(mk("1.2.3.4", "crowdsec", 4*time.Hour))

	got := s.Snapshot(base)
	if want := base.Add(4 * time.Hour); !got[0].ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v", got[0].ExpiresAt, want)
	}
}

func TestSetDelete(t *testing.T) {
	s := NewSet(0, OriginFilter{})
	s.Upsert(mk("1.2.3.4", "crowdsec", time.Hour))
	s.Upsert(mk("5.6.7.8", "crowdsec", time.Hour))

	if !s.Delete("1.2.3.4") {
		t.Error("Delete() of present key returned false")
	}
	if s.Delete("1.2.3.4") {
		t.Error("Delete() of absent key returned true")
	}

	got := keysOf(s.Snapshot(base))
	if len(got) != 1 || got[0] != "5.6.7.8" {
		t.Errorf("after delete, snapshot = %v, want [5.6.7.8]", got)
	}
}

func TestSnapshotDropsExpired(t *testing.T) {
	s := NewSet(0, OriginFilter{})
	s.Upsert(mk("1.2.3.4", "crowdsec", time.Hour))
	s.Upsert(mk("5.6.7.8", "crowdsec", 10*time.Minute))

	// 30 minutes later, only the 1h ban is still active.
	got := keysOf(s.Snapshot(base.Add(30 * time.Minute)))
	if len(got) != 1 || got[0] != "1.2.3.4" {
		t.Errorf("snapshot = %v, want [1.2.3.4]", got)
	}
}

func TestSnapshotOriginPriority(t *testing.T) {
	// Local scenarios outrank blocklists, which outrank CAPI, which outranks
	// anything unrecognised. This ordering is what the cap trims against.
	s := NewSet(0, OriginFilter{})
	s.Upsert(mk("4.4.4.4", "somethingelse", time.Hour))
	s.Upsert(mk("3.3.3.3", "CAPI", time.Hour))
	s.Upsert(mk("2.2.2.2", "lists:tor", time.Hour))
	s.Upsert(mk("1.1.1.1", "crowdsec", time.Hour))

	got := keysOf(s.Snapshot(base))
	want := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("snapshot order = %v, want %v", got, want)
		}
	}
}

func TestSnapshotOrdersByRemainingWithinOrigin(t *testing.T) {
	s := NewSet(0, OriginFilter{})
	s.Upsert(mk("1.1.1.1", "crowdsec", time.Hour))
	s.Upsert(mk("2.2.2.2", "crowdsec", 4*time.Hour))
	s.Upsert(mk("3.3.3.3", "crowdsec", 2*time.Hour))

	got := keysOf(s.Snapshot(base))
	want := []string{"2.2.2.2", "3.3.3.3", "1.1.1.1"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("snapshot order = %v, want %v (longest ban first)", got, want)
		}
	}
}

func TestSnapshotIsDeterministic(t *testing.T) {
	// Equal priority and equal expiry must still yield a stable order, otherwise
	// the reconciler would compute spurious deltas between runs.
	s := NewSet(0, OriginFilter{})
	for _, ip := range []string{"3.3.3.3", "1.1.1.1", "2.2.2.2"} {
		s.Upsert(mk(ip, "crowdsec", time.Hour))
	}

	first := keysOf(s.Snapshot(base))
	for i := 0; i < 20; i++ {
		if got := keysOf(s.Snapshot(base)); fmt.Sprint(got) != fmt.Sprint(first) {
			t.Fatalf("snapshot order unstable: %v then %v", first, got)
		}
	}
}

func TestSnapshotEnforcesCap(t *testing.T) {
	// The cap is the direct guard against exhausting router memory.
	s := NewSet(2, OriginFilter{})
	s.Upsert(mk("1.1.1.1", "crowdsec", time.Hour))
	s.Upsert(mk("2.2.2.2", "lists:tor", time.Hour))
	s.Upsert(mk("3.3.3.3", "CAPI", time.Hour))

	got := keysOf(s.Snapshot(base))
	if len(got) != 2 {
		t.Fatalf("snapshot has %d entries (%v), want 2", len(got), got)
	}
	want := []string{"1.1.1.1", "2.2.2.2"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("cap kept %v, want %v (highest priority survives)", got, want)
		}
	}
}

func TestSnapshotCapZeroMeansUnlimited(t *testing.T) {
	s := NewSet(0, OriginFilter{})
	for i := 0; i < 50; i++ {
		s.Upsert(mk(fmt.Sprintf("10.0.0.%d", i), "crowdsec", time.Hour))
	}
	if got := s.Snapshot(base); len(got) != 50 {
		t.Errorf("snapshot has %d entries, want 50 (cap 0 = unlimited)", len(got))
	}
}

// The cap must be applied to the live set, not to insertion order: a
// high-priority decision arriving after the cap is already reached still wins.
func TestSnapshotCapPrefersLatePriorityArrival(t *testing.T) {
	s := NewSet(1, OriginFilter{})
	s.Upsert(mk("3.3.3.3", "CAPI", time.Hour))
	s.Upsert(mk("1.1.1.1", "crowdsec", time.Hour))

	got := keysOf(s.Snapshot(base))
	if len(got) != 1 || got[0] != "1.1.1.1" {
		t.Errorf("snapshot = %v, want [1.1.1.1]", got)
	}
}

func TestOriginFilterExclude(t *testing.T) {
	s := NewSet(0, OriginFilter{Exclude: []string{"lists:huge"}})
	s.Upsert(mk("1.1.1.1", "crowdsec", time.Hour))
	s.Upsert(mk("2.2.2.2", "lists:huge", time.Hour))

	got := keysOf(s.Snapshot(base))
	if len(got) != 1 || got[0] != "1.1.1.1" {
		t.Errorf("snapshot = %v, want [1.1.1.1]", got)
	}
}

func TestOriginFilterInclude(t *testing.T) {
	s := NewSet(0, OriginFilter{Include: []string{"crowdsec"}})
	s.Upsert(mk("1.1.1.1", "crowdsec", time.Hour))
	s.Upsert(mk("2.2.2.2", "CAPI", time.Hour))

	got := keysOf(s.Snapshot(base))
	if len(got) != 1 || got[0] != "1.1.1.1" {
		t.Errorf("snapshot = %v, want [1.1.1.1]", got)
	}
}

func TestOriginFilterExcludeWinsOverInclude(t *testing.T) {
	s := NewSet(0, OriginFilter{Include: []string{"crowdsec"}, Exclude: []string{"crowdsec"}})
	s.Upsert(mk("1.1.1.1", "crowdsec", time.Hour))

	if got := s.Snapshot(base); len(got) != 0 {
		t.Errorf("snapshot = %v, want empty (exclude must win)", keysOf(got))
	}
}

func TestSnapshotByFamily(t *testing.T) {
	// The reconciler drives one address-list per family, so it needs them split.
	s := NewSet(0, OriginFilter{})
	s.Upsert(mk("1.1.1.1", "crowdsec", time.Hour))
	s.Upsert(mk("2001:db8::1", "crowdsec", time.Hour))
	s.Upsert(mk("10.0.0.0/24", "crowdsec", time.Hour))

	v4, v6 := s.SnapshotByFamily(base)
	if len(v4) != 2 {
		t.Errorf("v4 snapshot = %v, want 2 entries", keysOf(v4))
	}
	if len(v6) != 1 || v6[0].Key != "2001:db8::1" {
		t.Errorf("v6 snapshot = %v, want [2001:db8::1]", keysOf(v6))
	}
}

// The cap is a total budget across both families; splitting must not let the
// combined entry count exceed what the router can hold.
func TestSnapshotByFamilyRespectsGlobalCap(t *testing.T) {
	s := NewSet(2, OriginFilter{})
	s.Upsert(mk("1.1.1.1", "crowdsec", 4*time.Hour))
	s.Upsert(mk("2001:db8::1", "crowdsec", 3*time.Hour))
	s.Upsert(mk("2.2.2.2", "CAPI", time.Hour))

	v4, v6 := s.SnapshotByFamily(base)
	if total := len(v4) + len(v6); total != 2 {
		t.Fatalf("total entries = %d (v4=%v v6=%v), want 2", total, keysOf(v4), keysOf(v6))
	}
}

func TestSetLen(t *testing.T) {
	s := NewSet(0, OriginFilter{})
	if s.Len() != 0 {
		t.Errorf("empty Len() = %d, want 0", s.Len())
	}
	s.Upsert(mk("1.1.1.1", "crowdsec", time.Hour))
	s.Upsert(mk("1.1.1.1", "crowdsec", time.Hour))
	if s.Len() != 1 {
		t.Errorf("Len() after duplicate upsert = %d, want 1", s.Len())
	}
}

// Bootstrapping a Console subscription means ~100k decisions in one burst.
// Snapshot must stay O(n log n); an O(n^2) cap would stall the bouncer here.
func TestSnapshotLargeVolume(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large volume test in short mode")
	}
	s := NewSet(20000, OriginFilter{})
	for i := 0; i < 100000; i++ {
		s.Upsert(mk(fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff), "lists:big", time.Hour))
	}
	got := s.Snapshot(base)
	if len(got) != 20000 {
		t.Fatalf("snapshot has %d entries, want 20000", len(got))
	}
}
