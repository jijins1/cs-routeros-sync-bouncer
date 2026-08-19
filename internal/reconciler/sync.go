package reconciler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/ruokki/cs-routeros-sync-bouncer/internal/decision"
	"github.com/ruokki/cs-routeros-sync-bouncer/internal/mikrotik"
)

// Options configures a Reconciler.
type Options struct {
	ListV4    string
	ListV6    string
	BatchSize int // .id values per remove call; 0 selects a default
	Logger    *slog.Logger
}

// Stats summarises one sync pass.
type Stats struct {
	Added   int
	Removed int
}

// Reconciler drives a router's address-lists towards a decision Set.
type Reconciler struct {
	client mikrotik.Client
	set    *decision.Set
	opts   Options
	log    *slog.Logger
}

// New returns a Reconciler.
func New(client mikrotik.Client, set *decision.Set, opts Options) *Reconciler {
	if opts.BatchSize <= 0 {
		opts.BatchSize = 100
	}
	if opts.ListV4 == "" {
		opts.ListV4 = "crowdsec-v4"
	}
	if opts.ListV6 == "" {
		opts.ListV6 = "crowdsec-v6"
	}
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}

	return &Reconciler{client: client, set: set, opts: opts, log: log}
}

// Sync makes one pass over both address-lists.
//
// Each pass reads the router's actual contents rather than trusting a local
// idea of what was sent previously. That read is the whole safety property: a
// bouncer that tracks only its own writes drifts, and every cycle of drift adds
// another copy of an address the router already holds.
//
// Errors on individual addresses are collected rather than aborting the pass,
// so one rejected entry cannot block every other ban behind it.
func (r *Reconciler) Sync(ctx context.Context, now time.Time) (Stats, error) {
	v4, v6 := r.set.SnapshotByFamily(now)

	var (
		stats Stats
		errs  []error
	)
	for _, task := range []struct {
		fam     mikrotik.Family
		list    string
		desired []decision.Decision
	}{
		{mikrotik.V4, r.opts.ListV4, v4},
		{mikrotik.V6, r.opts.ListV6, v6},
	} {
		s, err := r.syncList(ctx, task.fam, task.list, task.desired, now)
		stats.Added += s.Added
		stats.Removed += s.Removed
		if err != nil {
			if ctx.Err() != nil {
				return stats, err
			}
			errs = append(errs, err)
		}
	}

	return stats, errors.Join(errs...)
}

func (r *Reconciler) syncList(ctx context.Context, fam mikrotik.Family, list string, desired []decision.Decision, now time.Time) (Stats, error) {
	if err := ctx.Err(); err != nil {
		return Stats{}, err
	}

	actual, err := r.client.List(ctx, fam, list)
	if err != nil {
		return Stats{}, fmt.Errorf("read %s: %w", list, err)
	}

	plan := BuildPlan(fam, list, desired, actual, now)
	if plan.IsEmpty() {
		r.log.Debug("address-list already in sync", "list", list, "entries", len(desired))
		return Stats{}, nil
	}

	return r.apply(ctx, plan)
}

// apply executes a plan, removing before adding so the router releases memory
// before it is asked for more.
func (r *Reconciler) apply(ctx context.Context, plan Plan) (Stats, error) {
	var (
		stats Stats
		errs  []error
	)

	for chunk := range batches(plan.Remove, r.opts.BatchSize) {
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		if err := r.client.Remove(ctx, plan.Family, chunk); err != nil {
			errs = append(errs, fmt.Errorf("remove from %s: %w", plan.List, err))
			continue
		}
		stats.Removed += len(chunk)
	}

	for _, entry := range plan.Add {
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		if _, err := r.client.Add(ctx, plan.Family, entry); err != nil {
			errs = append(errs, fmt.Errorf("add %s to %s: %w", entry.Address, plan.List, err))
			continue
		}
		stats.Added++
	}

	if len(errs) > 0 {
		r.log.Warn("address-list sync partially failed",
			"list", plan.List, "added", stats.Added, "removed", stats.Removed, "errors", len(errs))
	} else {
		r.log.Info("address-list synced",
			"list", plan.List, "added", stats.Added, "removed", stats.Removed)
	}

	return stats, errors.Join(errs...)
}

// batches yields consecutive slices of at most size elements.
func batches[T any](items []T, size int) func(func([]T) bool) {
	return func(yield func([]T) bool) {
		for start := 0; start < len(items); start += size {
			end := min(start+size, len(items))
			if !yield(items[start:end]) {
				return
			}
		}
	}
}
