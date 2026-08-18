// Package reconciler brings a RouterOS address-list in line with the set of
// decisions that should be enforced.
package reconciler

import (
	"fmt"
	"time"

	"github.com/ruokki/cs-routeros-sync-bouncer/internal/decision"
	"github.com/ruokki/cs-routeros-sync-bouncer/internal/mikrotik"
)

// Plan is the work needed to make one address-list match the desired state.
type Plan struct {
	List   string
	Add    []mikrotik.Entry
	Remove []string // RouterOS .id values
}

// IsEmpty reports whether the router is already in the desired state.
func (p Plan) IsEmpty() bool {
	return len(p.Add) == 0 && len(p.Remove) == 0
}

func (p Plan) String() string {
	return fmt.Sprintf("plan(%s: +%d -%d)", p.List, len(p.Add), len(p.Remove))
}

// BuildPlan diffs the desired decisions against what the router actually holds.
//
// The whole point is that an address already present produces no work. The
// bouncer this replaces re-sent its full list on every cycle, so the router
// accumulated a copy of each address per pass until it ran out of memory; here
// a steady state costs zero writes.
//
// Three rules keep it safe and convergent:
//
//   - Entries without our marker belong to the operator. They are never
//     removed, and an address they already cover is not added a second time.
//   - Among several managed copies of the same address, one is kept and the
//     rest are removed. This actively repairs a list that a previous bouncer
//     already filled with duplicates.
//   - Addresses are compared in canonical form, because the router echoes
//     1.2.3.4/32 back as 1.2.3.4 and a textual comparison would treat that as
//     a difference on every pass.
func BuildPlan(list string, desired []decision.Decision, actual []mikrotik.Entry, now time.Time) Plan {
	plan := Plan{List: list}

	// Index what is on the router by canonical address.
	managed := make(map[string][]string, len(actual)) // address -> .id copies
	unmanaged := make(map[string]struct{}, len(actual))

	for _, entry := range actual {
		key, _, err := decision.Canonicalize(entry.Address)

		if !entry.Managed() {
			// Not ours to reason about; just remember that the address is
			// already covered so we do not add our own duplicate of it.
			if err == nil {
				unmanaged[key] = struct{}{}
			}
			continue
		}

		if err != nil {
			// One of ours that the router reports in a form we cannot parse.
			// It can never be matched, so it would live forever: drop it.
			plan.Remove = append(plan.Remove, entry.ID)
			continue
		}

		managed[key] = append(managed[key], entry.ID)
	}

	for _, d := range desired {
		copies, onRouter := managed[d.Key]

		if !onRouter {
			if _, covered := unmanaged[d.Key]; covered {
				continue
			}
			plan.Add = append(plan.Add, mikrotik.Entry{
				List:    list,
				Address: d.Key,
				Comment: mikrotik.ManagedComment,
				Timeout: d.RouterOSTimeout(now),
			})
			continue
		}

		// Present already: keep the first copy, discard any surplus.
		plan.Remove = append(plan.Remove, copies[1:]...)
		delete(managed, d.Key)
	}

	// Anything managed and left over is no longer wanted, in all its copies.
	for _, copies := range managed {
		plan.Remove = append(plan.Remove, copies...)
	}

	return plan
}
