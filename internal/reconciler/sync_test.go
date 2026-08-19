package reconciler

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ruokki/cs-routeros-sync-bouncer/internal/decision"
	"github.com/ruokki/cs-routeros-sync-bouncer/internal/mikrotik"
)

// fakeClient is an in-memory stand-in for a router. It records the calls made
// against it so tests can assert on the write traffic, which is the thing that
// actually hurt the router in the original bug.
type fakeClient struct {
	mu sync.Mutex

	lists map[string][]mikrotik.Entry

	addCalls    int
	removeCalls int
	removedIDs  []string
	listCalls   int

	nextID  int
	addErr  error
	listErr error
	rmErr   error

	// families records the Family each list was addressed with.
	families map[string]mikrotik.Family
}

func newFakeClient() *fakeClient {
	return &fakeClient{lists: map[string][]mikrotik.Entry{}}
}

func (f *fakeClient) seed(list string, entries ...mikrotik.Entry) {
	f.lists[list] = append(f.lists[list], entries...)
}

func (f *fakeClient) List(ctx context.Context, fam mikrotik.Family, list string) ([]mikrotik.Entry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listCalls++
	f.famFor(list, fam)
	if f.listErr != nil {
		return nil, f.listErr
	}
	return append([]mikrotik.Entry(nil), f.lists[list]...), nil
}

func (f *fakeClient) Add(ctx context.Context, fam mikrotik.Family, e mikrotik.Entry) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addCalls++
	f.famFor(e.List, fam)
	if f.addErr != nil {
		return "", f.addErr
	}
	f.nextID++
	e.ID = fmt.Sprintf("*%d", f.nextID)
	f.lists[e.List] = append(f.lists[e.List], e)
	return e.ID, nil
}

func (f *fakeClient) Remove(ctx context.Context, fam mikrotik.Family, ids []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removeCalls++
	if f.rmErr != nil {
		return f.rmErr
	}
	f.removedIDs = append(f.removedIDs, ids...)

	drop := make(map[string]bool, len(ids))
	for _, id := range ids {
		drop[id] = true
	}
	for list, entries := range f.lists {
		kept := entries[:0]
		for _, e := range entries {
			if !drop[e.ID] {
				kept = append(kept, e)
			}
		}
		f.lists[list] = kept
	}
	return nil
}

func (f *fakeClient) Close() error { return nil }

// famFor records which family each list was addressed with, so a test can
// assert that IPv6 work is not sent to the IPv4 table. Caller holds f.mu.
func (f *fakeClient) famFor(list string, fam mikrotik.Family) {
	if f.families == nil {
		f.families = map[string]mikrotik.Family{}
	}
	f.families[list] = fam
}

func (f *fakeClient) addressesIn(list string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.lists[list]))
	for _, e := range f.lists[list] {
		out = append(out, e.Address)
	}
	return out
}

func testReconciler(c mikrotik.Client, set *decision.Set) *Reconciler {
	return New(c, set, Options{
		ListV4:    "crowdsec-v4",
		ListV6:    "crowdsec-v6",
		BatchSize: 100,
	})
}

func setWith(ds ...decision.Decision) *decision.Set {
	s := decision.NewSet(0, decision.OriginFilter{})
	for _, d := range ds {
		s.Upsert(d)
	}
	return s
}

func TestSyncAddsMissingEntries(t *testing.T) {
	c := newFakeClient()
	r := testReconciler(c, setWith(want("1.2.3.4", time.Hour), want("2001:db8::1", time.Hour)))

	stats, err := r.Sync(context.Background(), now)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if stats.Added != 2 {
		t.Errorf("Added = %d, want 2", stats.Added)
	}
	if got := c.addressesIn("crowdsec-v4"); len(got) != 1 || got[0] != "1.2.3.4" {
		t.Errorf("v4 list = %v, want [1.2.3.4]", got)
	}
	if got := c.addressesIn("crowdsec-v6"); len(got) != 1 || got[0] != "2001:db8::1" {
		t.Errorf("v6 list = %v, want [2001:db8::1]", got)
	}
}

// The defining property of this bouncer: once the router matches, repeated
// syncs must not write anything at all.
func TestSyncIsIdempotent(t *testing.T) {
	c := newFakeClient()
	r := testReconciler(c, setWith(want("1.2.3.4", time.Hour), want("5.6.7.8", time.Hour)))

	if _, err := r.Sync(context.Background(), now); err != nil {
		t.Fatalf("first Sync: %v", err)
	}
	addsAfterFirst := c.addCalls

	for i := 0; i < 5; i++ {
		if _, err := r.Sync(context.Background(), now); err != nil {
			t.Fatalf("Sync %d: %v", i, err)
		}
	}

	if c.addCalls != addsAfterFirst {
		t.Errorf("Add calls grew from %d to %d across repeated syncs: the router is being churned",
			addsAfterFirst, c.addCalls)
	}
	if c.removeCalls != 0 {
		t.Errorf("Remove calls = %d, want 0", c.removeCalls)
	}
	if got := len(c.addressesIn("crowdsec-v4")); got != 2 {
		t.Errorf("v4 list has %d entries after 6 syncs, want 2: duplicates are accumulating", got)
	}
}

func TestSyncRemovesRevoked(t *testing.T) {
	c := newFakeClient()
	c.seed("crowdsec-v4", mikrotik.Entry{ID: "*1", List: "crowdsec-v4", Address: "9.9.9.9", Comment: mikrotik.ManagedComment})

	r := testReconciler(c, setWith(want("1.2.3.4", time.Hour)))
	stats, err := r.Sync(context.Background(), now)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}

	if stats.Removed != 1 {
		t.Errorf("Removed = %d, want 1", stats.Removed)
	}
	if got := c.addressesIn("crowdsec-v4"); len(got) != 1 || got[0] != "1.2.3.4" {
		t.Errorf("v4 list = %v, want [1.2.3.4]", got)
	}
}

// Cleaning up the mess left behind by the previous bouncer.
func TestSyncCollapsesPreExistingDuplicates(t *testing.T) {
	c := newFakeClient()
	for i := 1; i <= 4; i++ {
		c.seed("crowdsec-v4", mikrotik.Entry{
			ID: fmt.Sprintf("*%d", i), List: "crowdsec-v4",
			Address: "1.2.3.4", Comment: mikrotik.ManagedComment,
		})
	}

	r := testReconciler(c, setWith(want("1.2.3.4", time.Hour)))
	stats, err := r.Sync(context.Background(), now)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}

	if stats.Removed != 3 {
		t.Errorf("Removed = %d, want 3", stats.Removed)
	}
	if got := c.addressesIn("crowdsec-v4"); len(got) != 1 {
		t.Errorf("v4 list = %v, want a single copy", got)
	}
}

func TestSyncLeavesUnmanagedEntriesAlone(t *testing.T) {
	c := newFakeClient()
	c.seed("crowdsec-v4", mikrotik.Entry{ID: "*1", List: "crowdsec-v4", Address: "10.0.0.1", Comment: "office VPN"})

	r := testReconciler(c, setWith(want("1.2.3.4", time.Hour)))
	if _, err := r.Sync(context.Background(), now); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	if len(c.removedIDs) != 0 {
		t.Errorf("removed %v, want nothing: operator entries are off-limits", c.removedIDs)
	}
}

// Removals are issued before additions so the router frees memory before it is
// asked to allocate more.
func TestSyncRemovesBeforeAdding(t *testing.T) {
	c := newFakeClient()
	c.seed("crowdsec-v4", mikrotik.Entry{ID: "*1", List: "crowdsec-v4", Address: "9.9.9.9", Comment: mikrotik.ManagedComment})

	order := make([]string, 0, 2)
	r := testReconciler(&orderRecorder{fakeClient: c, order: &order}, setWith(want("1.2.3.4", time.Hour)))
	if _, err := r.Sync(context.Background(), now); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	if len(order) < 2 || order[0] != "remove" {
		t.Errorf("call order = %v, want remove before add", order)
	}
}

func TestSyncBatchesRemovals(t *testing.T) {
	c := newFakeClient()
	for i := 1; i <= 250; i++ {
		c.seed("crowdsec-v4", mikrotik.Entry{
			ID: fmt.Sprintf("*%d", i), List: "crowdsec-v4",
			Address: fmt.Sprintf("9.9.%d.%d", i>>8, i&0xff), Comment: mikrotik.ManagedComment,
		})
	}

	r := testReconciler(c, setWith())
	if _, err := r.Sync(context.Background(), now); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	// 250 entries at a batch size of 100 is three calls, not 250.
	if c.removeCalls != 3 {
		t.Errorf("Remove calls = %d, want 3 batches", c.removeCalls)
	}
	if len(c.removedIDs) != 250 {
		t.Errorf("removed %d ids, want 250", len(c.removedIDs))
	}
}

func TestSyncReportsListError(t *testing.T) {
	c := newFakeClient()
	c.listErr = errors.New("connection reset")

	r := testReconciler(c, setWith(want("1.2.3.4", time.Hour)))
	if _, err := r.Sync(context.Background(), now); err == nil {
		t.Fatal("Sync succeeded despite a failing List")
	}
}

// A failure on one address must not abort the whole sync: the remaining bans
// are still worth applying.
func TestSyncContinuesAfterSingleAddFailure(t *testing.T) {
	c := newFakeClient()
	r := testReconciler(&flakyAdder{fakeClient: c, failOn: "1.2.3.4"},
		setWith(want("1.2.3.4", time.Hour), want("5.6.7.8", time.Hour)))

	stats, err := r.Sync(context.Background(), now)
	if err == nil {
		t.Fatal("Sync returned nil error despite a failed add")
	}
	if stats.Added != 1 {
		t.Errorf("Added = %d, want 1 (the healthy address should still land)", stats.Added)
	}
	if got := c.addressesIn("crowdsec-v4"); len(got) != 1 || got[0] != "5.6.7.8" {
		t.Errorf("v4 list = %v, want [5.6.7.8]", got)
	}
}

func TestSyncRespectsContextCancellation(t *testing.T) {
	c := newFakeClient()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	r := testReconciler(c, setWith(want("1.2.3.4", time.Hour)))
	if _, err := r.Sync(ctx, now); !errors.Is(err, context.Canceled) {
		t.Errorf("Sync error = %v, want context.Canceled", err)
	}
}

// orderRecorder notes whether removes precede adds.
type orderRecorder struct {
	*fakeClient
	order *[]string
}

func (o *orderRecorder) Add(ctx context.Context, fam mikrotik.Family, e mikrotik.Entry) (string, error) {
	*o.order = append(*o.order, "add")
	return o.fakeClient.Add(ctx, fam, e)
}

func (o *orderRecorder) Remove(ctx context.Context, fam mikrotik.Family, ids []string) error {
	*o.order = append(*o.order, "remove")
	return o.fakeClient.Remove(ctx, fam, ids)
}

// flakyAdder fails for one specific address.
type flakyAdder struct {
	*fakeClient
	failOn string
}

func (f *flakyAdder) Add(ctx context.Context, fam mikrotik.Family, e mikrotik.Entry) (string, error) {
	if e.Address == f.failOn {
		return "", errors.New("no such item")
	}
	return f.fakeClient.Add(ctx, fam, e)
}

// IPv4 and IPv6 address-lists are separate RouterOS tables. Sending an IPv6
// address to the IPv4 one makes the device try to resolve it as a hostname and
// reject it with "is not a valid dns name", so every v6 ban silently went
// unenforced. This pins each list to its own table.
func TestSyncAddressesEachFamilyToItsOwnTable(t *testing.T) {
	c := newFakeClient()
	r := testReconciler(c, setWith(
		want("1.2.3.4", time.Hour),
		want("2602:80d:1005::10", time.Hour),
	))

	if _, err := r.Sync(context.Background(), now); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	for list, want := range map[string]mikrotik.Family{
		"crowdsec-v4": mikrotik.V4,
		"crowdsec-v6": mikrotik.V6,
	} {
		if got := c.families[list]; got != want {
			t.Errorf("%s addressed as family %q, want %q", list, got, want)
		}
	}
}

// The family must select a different RouterOS path, not just travel alongside
// the call unused.
func TestFamilyPathsAreDistinct(t *testing.T) {
	if got := mikrotik.V4.Path(); got != "/ip/firewall/address-list" {
		t.Errorf("V4 path = %q", got)
	}
	if got := mikrotik.V6.Path(); got != "/ipv6/firewall/address-list" {
		t.Errorf("V6 path = %q", got)
	}
}
