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

	"github.com/ruokki/cs-routeros-sync-bouncer/internal/config"
	"github.com/ruokki/cs-routeros-sync-bouncer/internal/crowdsec"
	"github.com/ruokki/cs-routeros-sync-bouncer/internal/decision"
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

	set := decision.NewSet(cfg.MikroTik.MaxEntries, decision.OriginFilter{
		Include: cfg.Origins.Include,
		Exclude: cfg.Origins.Exclude,
	})

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

	log.Info("cs-routeros-sync-bouncer starting",
		"version", version,
		"router", cfg.MikroTik.Address,
		"lists", cfg.MikroTik.AddressListV4+"/"+cfg.MikroTik.AddressListV6,
		"max_entries", cfg.MikroTik.MaxEntries)

	errc := make(chan error, 1)
	go func() { errc <- stream.Run(ctx) }()

	if err := syncLoop(ctx, rec, changed, errc, cfg, log); err != nil {
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
	cfg *config.Config,
	log *slog.Logger,
) error {
	minInterval := cfg.CrowdSec.UpdateInterval
	ticker := time.NewTicker(cfg.MikroTik.ReconcileInterval)
	defer ticker.Stop()

	var lastSync time.Time
	started := false

	sync := func() {
		stats, err := rec.Sync(ctx, time.Now())
		lastSync = time.Now()
		if err != nil && ctx.Err() == nil {
			log.Error("sync failed", "error", err, "added", stats.Added, "removed", stats.Removed)
		}
	}

	for {
		select {
		case <-ctx.Done():
			log.Info("shutting down; address-list entries keep their timeouts and will expire on their own")
			return nil

		case err := <-errc:
			return err

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
