package metrics

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func newTestMetrics(t *testing.T) (*Metrics, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewRegistry()
	return New(reg, "v1.2.3"), reg
}

func TestBuildInfoCarriesTheVersion(t *testing.T) {
	_, reg := newTestMetrics(t)

	const want = `
# HELP routeros_bouncer_build_info Version of the running bouncer.
# TYPE routeros_bouncer_build_info gauge
routeros_bouncer_build_info{version="v1.2.3"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "routeros_bouncer_build_info"); err != nil {
		t.Error(err)
	}
}

// The gap between tracked and enforced is how an operator sees that
// max_entries is silently discarding bans.
func TestDecisionGaugesExposeTheCapGap(t *testing.T) {
	m, _ := newTestMetrics(t)
	m.SetDecisions(150, 90, 10)
	m.SetMaxEntries(100)

	if got := testutil.ToFloat64(m.tracked); got != 150 {
		t.Errorf("tracked = %v, want 150", got)
	}
	if got := testutil.ToFloat64(m.enforced.WithLabelValues("v4")); got != 90 {
		t.Errorf("enforced v4 = %v, want 90", got)
	}
	if got := testutil.ToFloat64(m.enforced.WithLabelValues("v6")); got != 10 {
		t.Errorf("enforced v6 = %v, want 10", got)
	}
	if got := testutil.ToFloat64(m.maxEntries); got != 100 {
		t.Errorf("max_entries = %v, want 100", got)
	}
}

func TestObserveSyncCountsSuccessAndFailureSeparately(t *testing.T) {
	m, _ := newTestMetrics(t)

	m.ObserveSync(3, 1, 250*time.Millisecond, nil)
	m.ObserveSync(0, 0, 10*time.Millisecond, errors.New("router refused"))

	if got := testutil.ToFloat64(m.syncs.WithLabelValues("success")); got != 1 {
		t.Errorf("success count = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.syncs.WithLabelValues("failure")); got != 1 {
		t.Errorf("failure count = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.added); got != 3 {
		t.Errorf("added = %v, want 3", got)
	}
	if got := testutil.ToFloat64(m.removed); got != 1 {
		t.Errorf("removed = %v, want 1", got)
	}
}

// A failed pass must not advance the freshness gauge: an alert on
// "last success is old" is the main thing this metric is for.
func TestFailedSyncDoesNotAdvanceLastSuccess(t *testing.T) {
	m, _ := newTestMetrics(t)

	m.ObserveSync(1, 0, time.Millisecond, nil)
	afterSuccess := testutil.ToFloat64(m.lastSuccess)
	if afterSuccess == 0 {
		t.Fatal("last success timestamp still zero after a successful pass")
	}

	m.ObserveSync(0, 0, time.Millisecond, errors.New("boom"))
	if got := testutil.ToFloat64(m.lastSuccess); got != afterSuccess {
		t.Errorf("last success moved on a failed pass: %v -> %v", afterSuccess, got)
	}
}

func TestHandlerServesTheRegistry(t *testing.T) {
	m, _ := newTestMetrics(t)
	if m.Handler() == nil {
		t.Fatal("Handler() is nil")
	}
}
