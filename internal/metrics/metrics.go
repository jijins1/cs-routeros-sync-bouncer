// Package metrics exposes the bouncer's state to Prometheus.
//
// The metrics are chosen around one question an operator cannot otherwise
// answer: is the router actually enforcing what CrowdSec decided? A bouncer
// that connects, polls and syncs without error is indistinguishable from one
// that silently drops every ban past a cap, so the tracked/enforced gap is
// exported alongside the cap itself.
package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const namespace = "routeros_bouncer"

// Metrics holds the collectors and the registry they belong to.
type Metrics struct {
	reg prometheus.Gatherer

	tracked    prometheus.Gauge
	enforced   *prometheus.GaugeVec
	maxEntries prometheus.Gauge

	syncs       *prometheus.CounterVec
	duration    prometheus.Histogram
	added       prometheus.Counter
	removed     prometheus.Counter
	lastSuccess prometheus.Gauge
}

// New registers the collectors on reg and returns them.
func New(reg prometheus.Registerer, version string) *Metrics {
	m := &Metrics{
		tracked: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Name: "decisions_tracked",
			Help: "Decisions currently held in memory, before the max_entries cap.",
		}),
		enforced: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Name: "decisions_enforced",
			Help: "Decisions actually pushed to the router, after the cap. A persistent shortfall against decisions_tracked means bans are being discarded.",
		}, []string{"family"}),
		maxEntries: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Name: "max_entries",
			Help: "Configured ceiling on router entries; 0 means uncapped.",
		}),
		syncs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "syncs_total",
			Help: "Reconcile passes, by outcome.",
		}, []string{"result"}),
		duration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace, Name: "sync_duration_seconds",
			Help:    "Time taken by a reconcile pass.",
			Buckets: prometheus.DefBuckets,
		}),
		added: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace, Name: "entries_added_total",
			Help: "Address-list entries created on the router.",
		}),
		removed: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace, Name: "entries_removed_total",
			Help: "Address-list entries deleted from the router.",
		}),
		lastSuccess: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Name: "last_successful_sync_timestamp_seconds",
			Help: "When the last fully successful pass completed. Alert on this going stale rather than on the error counter, which stays flat while the router is unreachable.",
		}),
	}

	buildInfo := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace, Name: "build_info",
		Help: "Version of the running bouncer.",
	}, []string{"version"})
	buildInfo.WithLabelValues(version).Set(1)

	reg.MustRegister(
		m.tracked, m.enforced, m.maxEntries,
		m.syncs, m.duration, m.added, m.removed, m.lastSuccess,
		buildInfo,
	)

	// A private registry starts empty, so the runtime and process collectors
	// that come free with the default one have to be added back. Goroutine
	// count and RSS are what tell an operator the bouncer is leaking rather
	// than merely idle.
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	// Both label values are created up front so a family with nothing to
	// enforce reports 0 rather than vanishing from the output.
	m.enforced.WithLabelValues("v4")
	m.enforced.WithLabelValues("v6")

	if g, ok := reg.(prometheus.Gatherer); ok {
		m.reg = g
	}
	return m
}

// SetDecisions records the desired state: everything held, and what survived
// the cap for each family.
func (m *Metrics) SetDecisions(tracked, v4, v6 int) {
	m.tracked.Set(float64(tracked))
	m.enforced.WithLabelValues("v4").Set(float64(v4))
	m.enforced.WithLabelValues("v6").Set(float64(v6))
}

// SetMaxEntries publishes the configured cap so the gap against
// decisions_tracked can be read without knowing the deployment's config.
func (m *Metrics) SetMaxEntries(n int) { m.maxEntries.Set(float64(n)) }

// ObserveSync records one reconcile pass.
//
// A pass that failed part-way still added and removed what it managed to, so
// those counters advance either way; only the freshness gauge is withheld,
// because its whole purpose is to say when the router was last known correct.
func (m *Metrics) ObserveSync(added, removed int, d time.Duration, err error) {
	m.added.Add(float64(added))
	m.removed.Add(float64(removed))
	m.duration.Observe(d.Seconds())

	if err != nil {
		m.syncs.WithLabelValues("failure").Inc()
		return
	}
	m.syncs.WithLabelValues("success").Inc()
	m.lastSuccess.Set(float64(time.Now().Unix()))
}

// Handler serves the registry.
func (m *Metrics) Handler() http.Handler {
	if m.reg == nil {
		return promhttp.Handler()
	}
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}
