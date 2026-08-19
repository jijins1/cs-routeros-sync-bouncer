// Command cs-routeros-sync-bouncer enforces CrowdSec decisions in a MikroTik RouterOS
// firewall address-list.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/ruokki/cs-routeros-sync-bouncer/internal/config"
	"github.com/ruokki/cs-routeros-sync-bouncer/internal/crowdsec"
	"github.com/ruokki/cs-routeros-sync-bouncer/internal/decision"
	"github.com/ruokki/cs-routeros-sync-bouncer/internal/metrics"
	"github.com/ruokki/cs-routeros-sync-bouncer/internal/mikrotik"
	"github.com/ruokki/cs-routeros-sync-bouncer/internal/reconciler"
)

var version = "dev"

func main() {
	configPath := flag.String("config", "/etc/crowdsec/bouncers/cs-routeros-sync-bouncer.yaml", "path to the configuration file")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("cs-routeros-sync-bouncer", version)
		return
	}

	if err := run(*configPath); err != nil && !errors.Is(err, context.Canceled) {
		slog.Error("cs-routeros-sync-bouncer stopped", "error", err)
		os.Exit(1)
	}
}

func run(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	log := newLogger(cfg.LogLevel)
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Logged before dialling anything: the router connection and the LAPI
	// handshake below can each take the configured timeout, and an operator
	// staring at an empty log has no way to tell a slow start from a hang.
	log.Info("cs-routeros-sync-bouncer starting",
		"version", version,
		"router", cfg.MikroTik.Address,
		"lists", cfg.MikroTik.AddressListV4+"/"+cfg.MikroTik.AddressListV6,
		"max_entries", cfg.MikroTik.MaxEntries)

	// Started before the router and LAPI connections so a bouncer that is slow
	// to reach either is still scrapeable while it waits. A connection that
	// fails outright still ends the process; there the pod restart is the
	// signal, not the endpoint.
	var mx *metrics.Metrics
	metricsErr := make(chan error, 1)
	if cfg.Metrics.IsEnabled() {
		reg := prometheus.NewRegistry()
		mx = metrics.New(reg, version)
		mx.SetMaxEntries(cfg.MikroTik.MaxEntries)

		log.Info("serving metrics", "listen", cfg.Metrics.Listen, "path", "/metrics")
		go func() { metricsErr <- metrics.Serve(ctx, cfg.Metrics.Listen, mx.Handler()) }()
	}

	set := decision.NewSet(cfg.MikroTik.MaxEntries, decision.OriginFilter{
		Include: cfg.Origins.Include,
		Exclude: cfg.Origins.Exclude,
	})

	log.Info("connecting to RouterOS", "address", cfg.MikroTik.Address,
		"tls", cfg.MikroTik.TLS, "timeout", cfg.MikroTik.Timeout)

	router, err := mikrotik.NewRouterOS(ctx, mikrotik.Config{
		Address:            cfg.MikroTik.Address,
		Username:           cfg.MikroTik.Username,
		Password:           cfg.MikroTik.Password,
		TLS:                cfg.MikroTik.TLS,
		InsecureSkipVerify: cfg.MikroTik.InsecureSkipVerify,
		Timeout:            cfg.MikroTik.Timeout,
	})
	if err != nil {
		return err
	}
	defer router.Close()

	log.Info("connected to RouterOS; initialising the CrowdSec stream",
		"lapi", cfg.CrowdSec.URL)

	stream, err := crowdsec.NewStream(crowdsec.Config{
		URL:                cfg.CrowdSec.URL,
		APIKey:             cfg.CrowdSec.APIKey,
		UpdateInterval:     cfg.CrowdSec.UpdateInterval,
		InsecureSkipVerify: cfg.CrowdSec.InsecureSkipVerify,
		UserAgent:          "cs-routeros-sync-bouncer/" + version,
		Origins:            cfg.Origins.Include,
	}, set, log)
	if err != nil {
		return err
	}

	rec := reconciler.New(router, set, reconciler.Options{
		ListV4:    cfg.MikroTik.AddressListV4,
		ListV6:    cfg.MikroTik.AddressListV6,
		BatchSize: cfg.MikroTik.BatchSize,
		Logger:    log,
	})

	// The stream signals here whenever it has changed the desired state.
	changed := make(chan struct{}, 1)
	stream.OnChange = func() {
		select {
		case changed <- struct{}{}:
		default: // a sync is already pending; nothing to add
		}
	}

	log.Info("waiting for the first batch of decisions",
		"update_interval", cfg.CrowdSec.UpdateInterval,
		"reconcile_interval", cfg.MikroTik.ReconcileInterval)

	errc := make(chan error, 1)
	go func() { errc <- stream.Run(ctx) }()

	if err := syncLoop(ctx, rec, changed, errc, metricsErr, cfg, log, mx, set); err != nil {
		return err
	}
	return nil
}

// syncLoop drives reconciliation.
//
// It deliberately does not sync before the first batch of decisions has
// arrived: at startup the desired state is empty, and acting on it would strip
// the address-list bare and leave the network unprotected until the decisions
// came back.
//
// Once running, a sync is triggered by a change in the desired state, rate
// limited so a busy stream cannot hammer the router, and repeated on a timer
// even when nothing changes so that any drift on the device is corrected.
func syncLoop(
	ctx context.Context,
	rec *reconciler.Reconciler,
	changed <-chan struct{},
	errc <-chan error,
	metricsErr <-chan error,
	cfg *config.Config,
	log *slog.Logger,
	mx *metrics.Metrics,
	set *decision.Set,
) error {
	minInterval := cfg.CrowdSec.UpdateInterval
	ticker := time.NewTicker(cfg.MikroTik.ReconcileInterval)
	defer ticker.Stop()

	var lastSync time.Time
	started := false

	sync := func() {
		syncStart := time.Now()
		stats, err := rec.Sync(ctx, syncStart)
		lastSync = time.Now()

		if mx != nil {
			v4, v6 := set.SnapshotByFamily(lastSync)
			mx.SetDecisions(set.Len(), len(v4), len(v6))
			mx.ObserveSync(stats.Added, stats.Removed, lastSync.Sub(syncStart), err)
		}
		if err != nil && ctx.Err() == nil {
			log.Error("sync failed", "error", err, "added", stats.Added, "removed", stats.Removed)
			return
		}
		// A pass that changed nothing is the steady state and would be pure
		// noise every reconcile_interval, so it stays at debug. A pass that
		// touched the router is the only evidence an operator has that the
		// bouncer is doing its job, so it is not hidden.
		if stats.Added > 0 || stats.Removed > 0 {
			log.Info("address-list synchronised", "added", stats.Added, "removed", stats.Removed)
		} else {
			log.Debug("address-list already in sync")
		}
	}

	for {
		select {
		case <-ctx.Done():
			log.Info("shutting down; address-list entries keep their timeouts and will expire on their own")
			return nil

		case err := <-errc:
			return err

		case err := <-metricsErr:
			// The endpoint failing is not worth dropping enforcement for, but
			// it must not be mistaken for a scrapeable bouncer either.
			if err != nil {
				log.Error("metrics endpoint stopped", "error", err)
			}

		case <-changed:
			if wait := minInterval - time.Since(lastSync); started && wait > 0 {
				// Coalesce with whatever else arrives in the meantime.
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(wait):
				}
			}
			started = true
			sync()
			ticker.Reset(cfg.MikroTik.ReconcileInterval)

		case <-ticker.C:
			if !started {
				log.Warn("no decisions received yet; not touching the address-list")
				continue
			}
			sync()
		}
	}
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}
