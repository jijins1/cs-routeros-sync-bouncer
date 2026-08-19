package reconciler

import (
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/ruokki/cs-routeros-sync-bouncer/internal/decision"
	"github.com/ruokki/cs-routeros-sync-bouncer/internal/mikrotik"
)

var now = time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)

func want(key string, ttl time.Duration) decision.Decision {
	k, fam, err := decision.Canonicalize(key)
	if err != nil {
		panic(err)
	}
	return decision.Decision{Key: k, Family: fam, Origin: "crowdsec", ExpiresAt: now.Add(ttl)}
}

// ours builds an entry as this bouncer would have written it.
func ours(id, address string) mikrotik.Entry {
	return mikrotik.Entry{ID: id, List: "crowdsec-v4", Address: address, Comment: mikrotik.ManagedComment, Timeout: "3600s"}
}

// theirs builds an entry the operator put there by hand.
func theirs(id, address, comment string) mikrotik.Entry {
	return mikrotik.Entry{ID: id, List: "crowdsec-v4", Address: address, Comment: comment}
}

func addedAddresses(p Plan) []string {
	out := make([]string, len(p.Add))
	for i, e := range p.Add {
		out[i] = e.Address
	}
	sort.Strings(out)
	return out
}

func sorted(ids []string) []string {
	out := append([]string(nil), ids...)
	sort.Strings(out)
	return out
}

// An address that is already on the router must produce no work at all.
// Re-adding it every cycle is precisely what exhausts the router's memory.
func TestPlanNoOpWhenAlreadyPresent(t *testing.T) {
	p := BuildPlan(mikrotik.V4, "crowdsec-v4",
		[]decision.Decision{want("1.2.3.4", time.Hour), want("5.6.7.8", time.Hour)},
		[]mikrotik.Entry{ours("*1", "1.2.3.4"), ours("*2", "5.6.7.8")},
		now)

	if !p.IsEmpty() {
		t.Fatalf("expected empty plan, got %s (add=%v remove=%v)", p, addedAddresses(p), p.Remove)
	}
}

func TestPlanAddsMissing(t *testing.T) {
	p := BuildPlan(mikrotik.V4, "crowdsec-v4",
		[]decision.Decision{want("1.2.3.4", time.Hour), want("5.6.7.8", time.Hour)},
		[]mikrotik.Entry{ours("*1", "1.2.3.4")},
		now)

	if got := addedAddresses(p); len(got) != 1 || got[0] != "5.6.7.8" {
		t.Errorf("Add = %v, want [5.6.7.8]", got)
	}
	if len(p.Remove) != 0 {
		t.Errorf("Remove = %v, want none", p.Remove)
	}
}

func TestPlanRemovesRevokedManagedEntry(t *testing.T) {
	p := BuildPlan(mikrotik.V4, "crowdsec-v4",
		[]decision.Decision{want("1.2.3.4", time.Hour)},
		[]mikrotik.Entry{ours("*1", "1.2.3.4"), ours("*2", "9.9.9.9")},
		now)

	if len(p.Add) != 0 {
		t.Errorf("Add = %v, want none", addedAddresses(p))
	}
	if got := p.Remove; len(got) != 1 || got[0] != "*2" {
		t.Errorf("Remove = %v, want [*2]", got)
	}
}

// Entries the operator added by hand carry no marker of ours. Touching them
// would be destructive, so they are invisible to the plan in both directions.
func TestPlanNeverTouchesUnmanagedEntries(t *testing.T) {
	p := BuildPlan(mikrotik.V4, "crowdsec-v4",
		[]decision.Decision{want("1.2.3.4", time.Hour)},
		[]mikrotik.Entry{
			theirs("*1", "10.0.0.1", "office VPN"),
			theirs("*2", "10.0.0.2", ""),
		},
		now)

	if len(p.Remove) != 0 {
		t.Fatalf("Remove = %v, want none: unmanaged entries must survive", p.Remove)
	}
	if got := addedAddresses(p); len(got) != 1 || got[0] != "1.2.3.4" {
		t.Errorf("Add = %v, want [1.2.3.4]", got)
	}
}

// If the operator has already blocked an address by hand, adding our own copy
// would be a second entry for the same address. Leave it to them.
func TestPlanSkipsAddressAlreadyCoveredByUnmanagedEntry(t *testing.T) {
	p := BuildPlan(mikrotik.V4, "crowdsec-v4",
		[]decision.Decision{want("10.0.0.1", time.Hour)},
		[]mikrotik.Entry{theirs("*1", "10.0.0.1", "office VPN")},
		now)

	if !p.IsEmpty() {
		t.Errorf("expected empty plan, got add=%v remove=%v", addedAddresses(p), p.Remove)
	}
}

// The reason this project exists: a previous bouncer left the same address in
// the list many times over. Reconciliation must collapse each address back to
// a single entry instead of adding to the pile.
func TestPlanCollapsesExistingDuplicates(t *testing.T) {
	p := BuildPlan(mikrotik.V4, "crowdsec-v4",
		[]decision.Decision{want("1.2.3.4", time.Hour)},
		[]mikrotik.Entry{
			ours("*1", "1.2.3.4"),
			ours("*2", "1.2.3.4"),
			ours("*3", "1.2.3.4"),
		},
		now)

	if len(p.Add) != 0 {
		t.Errorf("Add = %v, want none", addedAddresses(p))
	}
	if got := sorted(p.Remove); len(got) != 2 || got[0] != "*2" || got[1] != "*3" {
		t.Errorf("Remove = %v, want [*2 *3]: exactly one copy must survive", got)
	}
}

// Duplicates of an address that is no longer wanted must all go.
func TestPlanRemovesAllCopiesOfRevokedDuplicate(t *testing.T) {
	p := BuildPlan(mikrotik.V4, "crowdsec-v4", nil,
		[]mikrotik.Entry{ours("*1", "9.9.9.9"), ours("*2", "9.9.9.9")},
		now)

	if got := sorted(p.Remove); len(got) != 2 {
		t.Errorf("Remove = %v, want both copies", got)
	}
}

// The router reports 1.2.3.4/32 as 1.2.3.4. Comparing raw strings would see a
// difference that is not there and re-add the address on every single pass.
func TestPlanMatchesEquivalentAddressForms(t *testing.T) {
	p := BuildPlan(mikrotik.V4, "crowdsec-v4",
		[]decision.Decision{want("1.2.3.4/32", time.Hour), want("10.0.0.0/24", time.Hour)},
		[]mikrotik.Entry{ours("*1", "1.2.3.4"), ours("*2", "10.0.0.0/24")},
		now)

	if !p.IsEmpty() {
		t.Errorf("expected empty plan, got add=%v remove=%v", addedAddresses(p), p.Remove)
	}
}

// An entry the router cannot parse back is not something we can match against;
// it must be cleaned up rather than left to accumulate forever.
func TestPlanRemovesUnparsableManagedEntry(t *testing.T) {
	p := BuildPlan(mikrotik.V4, "crowdsec-v4", nil,
		[]mikrotik.Entry{{ID: "*1", List: "crowdsec-v4", Address: "not-an-ip", Comment: mikrotik.ManagedComment}},
		now)

	if got := p.Remove; len(got) != 1 || got[0] != "*1" {
		t.Errorf("Remove = %v, want [*1]", got)
	}
}

func TestPlanSetsListAndComment(t *testing.T) {
	p := BuildPlan(mikrotik.V4, "crowdsec-v6", []decision.Decision{want("2001:db8::1", time.Hour)}, nil, now)

	if len(p.Add) != 1 {
		t.Fatalf("Add has %d entries, want 1", len(p.Add))
	}
	e := p.Add[0]
	if e.List != "crowdsec-v6" {
		t.Errorf("List = %q, want crowdsec-v6", e.List)
	}
	if !e.Managed() {
		t.Errorf("Comment = %q, entry must be marked as managed", e.Comment)
	}
	if e.Address != "2001:db8::1" {
		t.Errorf("Address = %q, want 2001:db8::1", e.Address)
	}
}

// Every entry we create must expire on its own, so that a crashed or stopped
// bouncer cannot leave the router holding bans forever.
func TestPlanAlwaysSetsTimeout(t *testing.T) {
	p := BuildPlan(mikrotik.V4, "crowdsec-v4", []decision.Decision{want("1.2.3.4", 2*time.Hour)}, nil, now)

	if got := p.Add[0].Timeout; got != "7200s" {
		t.Errorf("Timeout = %q, want 7200s", got)
	}
}

func TestPlanEmptyOnBothSides(t *testing.T) {
	if p := BuildPlan(mikrotik.V4, "crowdsec-v4", nil, nil, now); !p.IsEmpty() {
		t.Errorf("expected empty plan, got %s", p)
	}
}

// A pass over an unchanged large list must produce no writes. If it does, the
// bouncer is churning the router and this is the bug we came to fix.
func TestPlanStableOverLargeUnchangedList(t *testing.T) {
	var desired []decision.Decision
	var actual []mikrotik.Entry
	for i := 0; i < 5000; i++ {
		addr := fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff)
		desired = append(desired, want(addr, time.Hour))
		actual = append(actual, ours(fmt.Sprintf("*%d", i+1), addr))
	}

	if p := BuildPlan(mikrotik.V4, "crowdsec-v4", desired, actual, now); !p.IsEmpty() {
		t.Fatalf("expected no work for unchanged list, got %s", p)
	}
}
