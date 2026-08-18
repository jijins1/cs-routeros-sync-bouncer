package crowdsec

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"

	"github.com/ruokki/cs-routeros-sync-bouncer/internal/decision"
)

var now = time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)

func ptr(s string) *string { return &s }

func dec(id int64, scope, value, origin, duration, typ string) *models.Decision {
	return &models.Decision{
		ID:       id,
		Scope:    ptr(scope),
		Value:    ptr(value),
		Origin:   ptr(origin),
		Duration: ptr(duration),
		Type:     ptr(typ),
	}
}

func testStream() (*Stream, *decision.Set) {
	set := decision.NewSet(0, decision.OriginFilter{})
	return &Stream{
		set: set,
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, set
}

func keys(ds []decision.Decision) []string {
	out := make([]string, len(ds))
	for i, d := range ds {
		out[i] = d.Key
	}
	return out
}

func TestApplyAddsNewBans(t *testing.T) {
	s, set := testStream()

	added, removed := s.Apply(&models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{
			dec(1, "Ip", "1.2.3.4", "crowdsec", "4h", "ban"),
			dec(2, "Range", "10.0.0.0/24", "lists:tor", "2h", "ban"),
		},
	}, now)

	if added != 2 || removed != 0 {
		t.Errorf("Apply = (%d, %d), want (2, 0)", added, removed)
	}
	if got := set.Snapshot(now); len(got) != 2 {
		t.Errorf("set = %v, want 2 addresses", keys(got))
	}
}

func TestApplyRemovesByID(t *testing.T) {
	s, set := testStream()
	s.Apply(&models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{dec(1, "Ip", "1.2.3.4", "crowdsec", "4h", "ban")},
	}, now)

	_, removed := s.Apply(&models.DecisionsStreamResponse{
		Deleted: models.GetDecisionsResponse{dec(1, "Ip", "1.2.3.4", "crowdsec", "4h", "ban")},
	}, now)

	if removed != 1 {
		t.Errorf("removed = %d, want 1", removed)
	}
	if got := set.Snapshot(now); len(got) != 0 {
		t.Errorf("set = %v, want empty", keys(got))
	}
}

// The reason decisions are reference counted: one scenario expiring must not
// unblock an address another scenario still bans.
func TestApplyKeepsAddressWhileAnotherDecisionStands(t *testing.T) {
	s, set := testStream()
	s.Apply(&models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{
			dec(1, "Ip", "1.2.3.4", "crowdsec", "4h", "ban"),
			dec(2, "Ip", "1.2.3.4", "crowdsec", "1h", "ban"),
		},
	}, now)

	s.Apply(&models.DecisionsStreamResponse{
		Deleted: models.GetDecisionsResponse{dec(2, "Ip", "1.2.3.4", "crowdsec", "1h", "ban")},
	}, now)

	if got := set.Snapshot(now); len(got) != 1 {
		t.Fatalf("set = %v, want the address still blocked", keys(got))
	}
}

// A router address-list can only drop traffic; a captcha decision is not ours
// to enforce and must not become a block.
func TestApplyIgnoresNonBanRemediations(t *testing.T) {
	s, set := testStream()

	added, _ := s.Apply(&models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{
			dec(1, "Ip", "1.2.3.4", "crowdsec", "4h", "captcha"),
			dec(2, "Ip", "5.6.7.8", "crowdsec", "4h", "ban"),
		},
	}, now)

	if added != 1 {
		t.Errorf("added = %d, want 1", added)
	}
	if got := keys(set.Snapshot(now)); len(got) != 1 || got[0] != "5.6.7.8" {
		t.Errorf("set = %v, want [5.6.7.8]", got)
	}
}

func TestApplySkipsNonAddressScopes(t *testing.T) {
	s, set := testStream()

	added, _ := s.Apply(&models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{
			dec(1, "Country", "RU", "crowdsec", "4h", "ban"),
			dec(2, "Username", "bob", "crowdsec", "4h", "ban"),
		},
	}, now)

	if added != 0 {
		t.Errorf("added = %d, want 0", added)
	}
	if got := set.Snapshot(now); len(got) != 0 {
		t.Errorf("set = %v, want empty", keys(got))
	}
}

// The LAPI sends optional fields as null; a nil dereference here would take
// the bouncer down and stop every ban.
func TestApplyToleratesNilFields(t *testing.T) {
	s, set := testStream()

	added, removed := s.Apply(&models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{
			{ID: 1}, // everything nil
			{ID: 2, Scope: ptr("Ip"), Value: ptr("1.2.3.4"), Duration: ptr("4h")}, // no origin, no type
			nil,
		},
		Deleted: models.GetDecisionsResponse{nil},
	}, now)

	if removed != 0 {
		t.Errorf("removed = %d, want 0", removed)
	}
	// The one with a usable address survives; a missing type is treated as a ban.
	if added != 1 {
		t.Errorf("added = %d, want 1", added)
	}
	if got := keys(set.Snapshot(now)); len(got) != 1 || got[0] != "1.2.3.4" {
		t.Errorf("set = %v, want [1.2.3.4]", got)
	}
}

func TestApplySkipsMalformedAddresses(t *testing.T) {
	s, set := testStream()

	added, _ := s.Apply(&models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{
			dec(1, "Ip", "not-an-ip", "crowdsec", "4h", "ban"),
			dec(2, "Ip", "1.2.3.4", "crowdsec", "not-a-duration", "ban"),
		},
	}, now)

	if added != 0 {
		t.Errorf("added = %d, want 0", added)
	}
	if got := set.Snapshot(now); len(got) != 0 {
		t.Errorf("set = %v, want empty", keys(got))
	}
}

// Deletions are folded in before additions, so a decision replaced by a longer
// one for the same address ends up blocked, not unblocked.
func TestApplyProcessesDeletionsFirst(t *testing.T) {
	s, set := testStream()
	s.Apply(&models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{dec(1, "Ip", "1.2.3.4", "crowdsec", "1h", "ban")},
	}, now)

	s.Apply(&models.DecisionsStreamResponse{
		Deleted: models.GetDecisionsResponse{dec(1, "Ip", "1.2.3.4", "crowdsec", "1h", "ban")},
		New:     models.GetDecisionsResponse{dec(2, "Ip", "1.2.3.4", "crowdsec", "8h", "ban")},
	}, now)

	got := set.Snapshot(now)
	if len(got) != 1 {
		t.Fatalf("set = %v, want the address blocked", keys(got))
	}
	if want := now.Add(8 * time.Hour); !got[0].ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v", got[0].ExpiresAt, want)
	}
}

// Re-delivery of the same message must be a no-op, not a second reference.
func TestApplyIsIdempotent(t *testing.T) {
	s, set := testStream()
	msg := &models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{dec(1, "Ip", "1.2.3.4", "crowdsec", "4h", "ban")},
	}

	s.Apply(msg, now)
	s.Apply(msg, now)

	if set.Len() != 1 {
		t.Errorf("set holds %d addresses, want 1", set.Len())
	}
	s.Apply(&models.DecisionsStreamResponse{
		Deleted: models.GetDecisionsResponse{dec(1, "Ip", "1.2.3.4", "crowdsec", "4h", "ban")},
	}, now)
	if got := set.Snapshot(now); len(got) != 0 {
		t.Errorf("set = %v, want empty after a single delete", keys(got))
	}
}
