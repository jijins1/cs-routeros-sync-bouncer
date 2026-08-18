package decision

import (
	"testing"
	"time"
)

func src(id int64, key, origin string, ttl time.Duration) Decision {
	d := mk(key, origin, ttl)
	d.ID = id
	return d
}

// Two scenarios banning the same address are two decisions over one entry.
// Losing one of them must not unblock the address while the other stands.
func TestForgetKeepsAddressWhileAnotherDecisionCoversIt(t *testing.T) {
	s := NewSet(0, OriginFilter{})
	s.Upsert(src(1, "1.2.3.4", "crowdsec", 4*time.Hour))
	s.Upsert(src(2, "1.2.3.4", "crowdsec", 2*time.Hour))

	if !s.Forget(2) {
		t.Fatal("Forget(2) returned false, want true")
	}

	got := s.Snapshot(base)
	if len(got) != 1 {
		t.Fatalf("snapshot = %v, want the address to remain blocked", keysOf(got))
	}
	if want := base.Add(4 * time.Hour); !got[0].ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v (surviving decision's expiry)", got[0].ExpiresAt, want)
	}
}

// Once the last decision covering an address is gone, the address goes too.
func TestForgetDropsAddressWithLastDecision(t *testing.T) {
	s := NewSet(0, OriginFilter{})
	s.Upsert(src(1, "1.2.3.4", "crowdsec", 4*time.Hour))
	s.Upsert(src(2, "1.2.3.4", "crowdsec", 2*time.Hour))

	s.Forget(1)
	s.Forget(2)

	if got := s.Snapshot(base); len(got) != 0 {
		t.Errorf("snapshot = %v, want empty", keysOf(got))
	}
}

func TestForgetUnknownDecision(t *testing.T) {
	s := NewSet(0, OriginFilter{})
	s.Upsert(src(1, "1.2.3.4", "crowdsec", time.Hour))

	if s.Forget(99) {
		t.Error("Forget of an unknown id returned true")
	}
	if got := s.Snapshot(base); len(got) != 1 {
		t.Errorf("snapshot = %v, want the address untouched", keysOf(got))
	}
}

// Expiry follows the longest-lived surviving decision, not the one removed.
func TestForgetRecomputesExpiryFromSurvivors(t *testing.T) {
	s := NewSet(0, OriginFilter{})
	s.Upsert(src(1, "1.2.3.4", "crowdsec", 4*time.Hour))
	s.Upsert(src(2, "1.2.3.4", "crowdsec", time.Hour))

	s.Forget(1) // the long one goes

	got := s.Snapshot(base)
	if len(got) != 1 {
		t.Fatalf("snapshot = %v, want one entry", keysOf(got))
	}
	if want := base.Add(time.Hour); !got[0].ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v", got[0].ExpiresAt, want)
	}
}

// Origin priority also follows the survivors, since it drives the cap.
func TestForgetRecomputesOriginFromSurvivors(t *testing.T) {
	s := NewSet(0, OriginFilter{})
	s.Upsert(src(1, "1.2.3.4", "crowdsec", time.Hour))
	s.Upsert(src(2, "1.2.3.4", "CAPI", time.Hour))

	s.Forget(1)

	got := s.Snapshot(base)
	if len(got) != 1 || got[0].Origin != "CAPI" {
		t.Errorf("origin = %q, want CAPI after the crowdsec decision is forgotten", got[0].Origin)
	}
}

// The winning origin is the best-ranked one covering the address, so a local
// scenario ban is not demoted by a blocklist that happens to list it too.
func TestUpsertKeepsBestOriginAcrossSources(t *testing.T) {
	s := NewSet(0, OriginFilter{})
	s.Upsert(src(1, "1.2.3.4", "lists:tor", time.Hour))
	s.Upsert(src(2, "1.2.3.4", "crowdsec", time.Hour))

	got := s.Snapshot(base)
	if len(got) != 1 || got[0].Origin != "crowdsec" {
		t.Errorf("origin = %q, want crowdsec", got[0].Origin)
	}
}

// Re-sending the same decision id must not inflate the reference count,
// otherwise a redelivered stream event would pin an address forever.
func TestUpsertSameDecisionTwiceIsOneReference(t *testing.T) {
	s := NewSet(0, OriginFilter{})
	s.Upsert(src(1, "1.2.3.4", "crowdsec", time.Hour))
	s.Upsert(src(1, "1.2.3.4", "crowdsec", time.Hour))

	s.Forget(1)

	if got := s.Snapshot(base); len(got) != 0 {
		t.Errorf("snapshot = %v, want empty: one id must count once", keysOf(got))
	}
}

// Expiring sources must not keep an address alive on their own.
func TestSnapshotDropsAddressWhenAllSourcesExpired(t *testing.T) {
	s := NewSet(0, OriginFilter{})
	s.Upsert(src(1, "1.2.3.4", "crowdsec", 30*time.Minute))
	s.Upsert(src(2, "1.2.3.4", "crowdsec", 10*time.Minute))

	if got := s.Snapshot(base.Add(time.Hour)); len(got) != 0 {
		t.Errorf("snapshot = %v, want empty once every source has elapsed", keysOf(got))
	}
}

// Delete removes the address outright regardless of how many decisions cover
// it; it is the blunt instrument used when the router state must be forced.
func TestDeleteDropsAllSources(t *testing.T) {
	s := NewSet(0, OriginFilter{})
	s.Upsert(src(1, "1.2.3.4", "crowdsec", time.Hour))
	s.Upsert(src(2, "1.2.3.4", "crowdsec", time.Hour))

	if !s.Delete("1.2.3.4") {
		t.Fatal("Delete returned false")
	}
	if got := s.Snapshot(base); len(got) != 0 {
		t.Errorf("snapshot = %v, want empty", keysOf(got))
	}
	// The forgotten ids must not linger in the id index.
	if s.Forget(1) || s.Forget(2) {
		t.Error("Forget succeeded after Delete: stale id index")
	}
}
