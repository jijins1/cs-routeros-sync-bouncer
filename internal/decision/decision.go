// Package decision holds the normalised representation of a CrowdSec decision
// and the deduplication logic that decides what should exist on the router.
//
// Nothing in this package talks to CrowdSec or to RouterOS: it is pure data
// handling, so the rules that actually protect the router from running out of
// memory can be tested without a router or a LAPI.
package decision

import (
	"fmt"
	"math"
	"net/netip"
	"strings"
	"time"
)

// Family distinguishes the two address-lists we maintain on the router.
type Family string

const (
	IPv4 Family = "v4"
	IPv6 Family = "v6"
)

// Decision is one entry we want to exist in a RouterOS address-list.
//
// Key is the canonical form of the address, and is the identity of the
// decision as far as this bouncer is concerned. Two CrowdSec decisions for the
// same address - different scenarios, different decision IDs - collapse onto a
// single Decision, which is what keeps the address-list free of duplicates.
type Decision struct {
	// ID is the CrowdSec decision id. Several decisions can cover one address,
	// so it is the unit of reference counting, not of identity on the router.
	ID        int64
	Key       string
	Family    Family
	Origin    string
	ExpiresAt time.Time
}

// Canonicalize converts a CrowdSec decision value into the exact string we
// will store on the router, and reports which address-list it belongs to.
//
// The normalisation matters for correctness, not tidiness: RouterOS stores
// "1.2.3.4/32" as "1.2.3.4", so without collapsing single-host prefixes the
// reconciler would see a phantom difference on every pass and add the address
// again and again.
func Canonicalize(value string) (string, Family, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", "", fmt.Errorf("empty address")
	}

	if strings.Contains(value, "/") {
		return canonicalizePrefix(value)
	}

	addr, err := netip.ParseAddr(value)
	if err != nil {
		return "", "", fmt.Errorf("invalid address %q: %w", value, err)
	}

	addr = addr.Unmap()

	return addr.String(), familyOf(addr), nil
}

func canonicalizePrefix(value string) (string, Family, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return "", "", fmt.Errorf("invalid prefix %q: %w", value, err)
	}

	// Drop any host bits so 10.0.0.5/24 and 10.0.0.0/24 are one entry.
	prefix = prefix.Masked()
	addr, bits := prefix.Addr(), prefix.Bits()

	// An IPv4-mapped IPv6 prefix describes an IPv4 range; carry the prefix
	// length across so ::ffff:1.2.3.0/120 becomes 1.2.3.0/24.
	if addr.Is4In6() {
		addr = addr.Unmap()
		bits -= 96
		if bits < 0 {
			return "", "", fmt.Errorf("invalid mapped prefix %q", value)
		}
	}

	// A prefix covering a single host is just that host, and RouterOS shows it
	// without the suffix.
	if bits == addr.BitLen() {
		return addr.String(), familyOf(addr), nil
	}

	return netip.PrefixFrom(addr, bits).String(), familyOf(addr), nil
}

func familyOf(addr netip.Addr) Family {
	if addr.Is4() {
		return IPv4
	}
	return IPv6
}

// Scopes we can express as an address-list entry. CrowdSec also emits
// Country, AS and Username decisions, which have no address to block.
const (
	scopeIP    = "ip"
	scopeRange = "range"
)

// FromStream normalises one decision from the LAPI stream.
//
// The returned bool reports whether the decision is actionable. A false with a
// nil error means the decision is valid but not ours to enforce - a country
// ban, or one that has already elapsed - and should be skipped quietly. An
// error means the decision was malformed and deserves a log line.
//
// duration is CrowdSec's relative form ("3h59m51.7s"), which is what the stream
// endpoint returns; it is resolved against now rather than trusting a
// wall-clock field, so a clock skew between LAPI and this host cannot produce
// an entry that never expires.
func FromStream(id int64, scope, value, origin, duration string, now time.Time) (Decision, bool, error) {
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case scopeIP, scopeRange:
	default:
		return Decision{}, false, nil
	}

	key, family, err := Canonicalize(value)
	if err != nil {
		return Decision{}, false, err
	}

	ttl, err := time.ParseDuration(strings.TrimSpace(duration))
	if err != nil {
		return Decision{}, false, fmt.Errorf("invalid duration %q for %s: %w", duration, key, err)
	}

	if ttl <= 0 {
		return Decision{}, false, nil
	}

	return Decision{
		ID:        id,
		Key:       key,
		Family:    family,
		Origin:    origin,
		ExpiresAt: now.Add(ttl),
	}, true, nil
}

// RouterOSTimeout renders the remaining lifetime in the form RouterOS expects.
//
// Every entry we add carries one. It is the safety net that matters most here:
// if this bouncer dies, the router still expires its own entries instead of
// accumulating them until it runs out of memory. A non-positive timeout means
// "never expire" to RouterOS, so it is clamped to one second rather than
// allowed through.
func (d Decision) RouterOSTimeout(now time.Time) string {
	remaining := d.ExpiresAt.Sub(now)
	if remaining < time.Second {
		return "1s"
	}
	return fmt.Sprintf("%ds", int64(math.Ceil(remaining.Seconds())))
}

// IsExpired reports whether the decision has elapsed as of now.
func (d Decision) IsExpired(now time.Time) bool {
	return !d.ExpiresAt.After(now)
}
