package crowdsec

import (
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

func countingStream() (*Stream, *int) {
	s, _ := testStream()
	calls := 0
	s.OnChange = func() { calls++ }
	return s, &calls
}

// At startup the desired state is empty. Reconciling then would delete every
// managed entry on the router and leave the network unprotected until the
// decisions came back, so the reconciler must not be woken until the first
// snapshot has landed - even when that snapshot is empty.
func TestApplyNotifiesOnFirstMessageEvenWhenEmpty(t *testing.T) {
	s, calls := countingStream()

	s.Apply(&models.DecisionsStreamResponse{}, now)

	if *calls != 1 {
		t.Errorf("OnChange called %d times, want 1: the empty snapshot still primes the reconciler", *calls)
	}
}

// Once primed, an idle poll changes nothing and must not trigger a router
// round trip.
func TestApplyDoesNotNotifyWhenNothingChanged(t *testing.T) {
	s, calls := countingStream()

	s.Apply(&models.DecisionsStreamResponse{}, now) // primes
	s.Apply(&models.DecisionsStreamResponse{}, now)
	s.Apply(&models.DecisionsStreamResponse{}, now)

	if *calls != 1 {
		t.Errorf("OnChange called %d times, want 1: idle polls must not wake the reconciler", *calls)
	}
}

func TestApplyNotifiesOnNewDecision(t *testing.T) {
	s, calls := countingStream()

	s.Apply(&models.DecisionsStreamResponse{}, now) // primes
	s.Apply(&models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{dec(1, "Ip", "1.2.3.4", "crowdsec", "4h", "ban")},
	}, now)

	if *calls != 2 {
		t.Errorf("OnChange called %d times, want 2", *calls)
	}
}

func TestApplyNotifiesOnDeletion(t *testing.T) {
	s, calls := countingStream()

	s.Apply(&models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{dec(1, "Ip", "1.2.3.4", "crowdsec", "4h", "ban")},
	}, now)
	before := *calls

	s.Apply(&models.DecisionsStreamResponse{
		Deleted: models.GetDecisionsResponse{dec(1, "Ip", "1.2.3.4", "crowdsec", "4h", "ban")},
	}, now)

	if *calls != before+1 {
		t.Errorf("OnChange called %d times, want %d", *calls, before+1)
	}
}

// Decisions that are filtered out do not change the desired state, so they
// must not cause a sync either.
func TestApplyDoesNotNotifyForIgnoredDecisions(t *testing.T) {
	s, calls := countingStream()

	s.Apply(&models.DecisionsStreamResponse{}, now) // primes
	s.Apply(&models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{
			dec(1, "Country", "RU", "crowdsec", "4h", "ban"),
			dec(2, "Ip", "1.2.3.4", "crowdsec", "4h", "captcha"),
		},
	}, now)

	if *calls != 1 {
		t.Errorf("OnChange called %d times, want 1", *calls)
	}
}

// A nil callback is the normal case in tests and when running without a
// reconciler attached; it must not panic.
func TestApplyWithoutCallback(t *testing.T) {
	s, _ := testStream()
	s.Apply(&models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{dec(1, "Ip", "1.2.3.4", "crowdsec", "4h", "ban")},
	}, now)
}
