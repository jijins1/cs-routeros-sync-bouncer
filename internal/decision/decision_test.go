package decision

import (
	"testing"
	"time"
)

func TestCanonicalize(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantKey string
		wantFam Family
		wantErr bool
	}{
		// Bare addresses
		{name: "ipv4 bare", in: "1.2.3.4", wantKey: "1.2.3.4", wantFam: IPv4},
		{name: "ipv6 bare", in: "2001:db8::1", wantKey: "2001:db8::1", wantFam: IPv6},

		// Case / form normalisation: RouterOS and CrowdSec may disagree on casing.
		{name: "ipv6 uppercase is lowercased", in: "2001:DB8::1", wantKey: "2001:db8::1", wantFam: IPv6},
		{name: "ipv6 expanded is compressed", in: "2001:0db8:0000:0000:0000:0000:0000:0001", wantKey: "2001:db8::1", wantFam: IPv6},

		// Single-host prefixes collapse to bare addresses. This is the dedup case
		// that produces duplicate address-list entries if left unhandled.
		{name: "ipv4 /32 collapses to bare", in: "1.2.3.4/32", wantKey: "1.2.3.4", wantFam: IPv4},
		{name: "ipv6 /128 collapses to bare", in: "2001:db8::1/128", wantKey: "2001:db8::1", wantFam: IPv6},

		// Real prefixes are kept, but masked to their network address so that
		// 10.0.0.5/24 and 10.0.0.0/24 do not become two entries.
		{name: "ipv4 prefix kept", in: "10.0.0.0/24", wantKey: "10.0.0.0/24", wantFam: IPv4},
		{name: "ipv4 prefix masked", in: "10.0.0.5/24", wantKey: "10.0.0.0/24", wantFam: IPv4},
		{name: "ipv6 prefix kept", in: "2001:db8::/32", wantKey: "2001:db8::/32", wantFam: IPv6},
		{name: "ipv6 prefix masked", in: "2001:db8::5/32", wantKey: "2001:db8::/32", wantFam: IPv6},

		// Whitespace is tolerated, everything else is rejected.
		{name: "surrounding whitespace trimmed", in: "  1.2.3.4  ", wantKey: "1.2.3.4", wantFam: IPv4},
		{name: "empty rejected", in: "", wantErr: true},
		{name: "garbage rejected", in: "not-an-ip", wantErr: true},
		{name: "hostname rejected", in: "example.com", wantErr: true},
		{name: "bad prefix rejected", in: "1.2.3.4/33", wantErr: true},

		// IPv4-mapped IPv6 must not masquerade as a distinct v6 entry.
		{name: "ipv4-mapped v6 becomes ipv4", in: "::ffff:1.2.3.4", wantKey: "1.2.3.4", wantFam: IPv4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, fam, err := Canonicalize(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Canonicalize(%q) = (%q, %q, nil), want error", tt.in, key, fam)
				}
				return
			}
			if err != nil {
				t.Fatalf("Canonicalize(%q) returned unexpected error: %v", tt.in, err)
			}
			if key != tt.wantKey {
				t.Errorf("Canonicalize(%q) key = %q, want %q", tt.in, key, tt.wantKey)
			}
			if fam != tt.wantFam {
				t.Errorf("Canonicalize(%q) family = %q, want %q", tt.in, fam, tt.wantFam)
			}
		})
	}
}

// Canonicalize must be idempotent: feeding its own output back in is a no-op.
// The reconciler relies on this when comparing router state against desired state.
func TestCanonicalizeIsIdempotent(t *testing.T) {
	inputs := []string{"1.2.3.4", "1.2.3.4/32", "10.0.0.5/24", "2001:DB8::1", "2001:db8::5/32"}
	for _, in := range inputs {
		once, fam1, err := Canonicalize(in)
		if err != nil {
			t.Fatalf("Canonicalize(%q): %v", in, err)
		}
		twice, fam2, err := Canonicalize(once)
		if err != nil {
			t.Fatalf("Canonicalize(%q) [second pass]: %v", once, err)
		}
		if once != twice || fam1 != fam2 {
			t.Errorf("Canonicalize not idempotent for %q: %q/%q then %q/%q", in, once, fam1, twice, fam2)
		}
	}
}

func TestFromStream(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name      string
		scope     string
		value     string
		origin    string
		duration  string
		wantOK    bool
		wantErr   bool
		wantKey   string
		wantUntil time.Time
	}{
		{
			name: "plain ip ban", scope: "Ip", value: "1.2.3.4",
			origin: "crowdsec", duration: "4h",
			wantOK: true, wantKey: "1.2.3.4", wantUntil: now.Add(4 * time.Hour),
		},
		{
			name: "range ban", scope: "Range", value: "10.0.0.0/24",
			origin: "lists:foo", duration: "1h30m",
			wantOK: true, wantKey: "10.0.0.0/24", wantUntil: now.Add(90 * time.Minute),
		},
		{
			name: "scope is case insensitive", scope: "ip", value: "1.2.3.4",
			origin: "crowdsec", duration: "4h",
			wantOK: true, wantKey: "1.2.3.4", wantUntil: now.Add(4 * time.Hour),
		},
		{
			name: "crowdsec sub-second duration format", scope: "Ip", value: "1.2.3.4",
			origin: "CAPI", duration: "3h59m51.7s",
			wantOK: true, wantKey: "1.2.3.4", wantUntil: now.Add(3*time.Hour + 59*time.Minute + 51*time.Second + 700*time.Millisecond),
		},

		// Scopes that cannot be expressed as a RouterOS address-list entry are
		// skipped without error - they are legitimate decisions, just not ours.
		{name: "country scope skipped", scope: "Country", value: "RU", origin: "crowdsec", duration: "4h", wantOK: false},
		{name: "as scope skipped", scope: "AS", value: "12345", origin: "crowdsec", duration: "4h", wantOK: false},
		{name: "username scope skipped", scope: "Username", value: "bob", origin: "crowdsec", duration: "4h", wantOK: false},

		// An already-elapsed decision must not be pushed to the router.
		{name: "expired duration skipped", scope: "Ip", value: "1.2.3.4", origin: "crowdsec", duration: "-5m", wantOK: false},
		{name: "zero duration skipped", scope: "Ip", value: "1.2.3.4", origin: "crowdsec", duration: "0s", wantOK: false},

		// Malformed input is an error, not a silent skip: we want it in the logs.
		{name: "bad ip errors", scope: "Ip", value: "nope", origin: "crowdsec", duration: "4h", wantErr: true},
		{name: "bad duration errors", scope: "Ip", value: "1.2.3.4", origin: "crowdsec", duration: "forever", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, ok, err := FromStream(7, tt.scope, tt.value, tt.origin, tt.duration, now)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("FromStream(...) = (%+v, %v, nil), want error", d, ok)
				}
				return
			}
			if err != nil {
				t.Fatalf("FromStream(...) unexpected error: %v", err)
			}
			if ok != tt.wantOK {
				t.Fatalf("FromStream(...) ok = %v, want %v", ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if d.Key != tt.wantKey {
				t.Errorf("Key = %q, want %q", d.Key, tt.wantKey)
			}
			if !d.ExpiresAt.Equal(tt.wantUntil) {
				t.Errorf("ExpiresAt = %v, want %v", d.ExpiresAt, tt.wantUntil)
			}
			if d.Origin != tt.origin {
				t.Errorf("Origin = %q, want %q", d.Origin, tt.origin)
			}
		})
	}
}

func TestRouterOSTimeout(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		in   time.Duration
		want string
	}{
		{name: "whole hours", in: 4 * time.Hour, want: "14400s"},
		{name: "sub-second rounds up to 1s", in: 500 * time.Millisecond, want: "1s"},
		{name: "fractional seconds round up", in: 90*time.Second + 400*time.Millisecond, want: "91s"},
		// A non-positive timeout would mean "never expire" in RouterOS, which is
		// exactly the leak we are trying to avoid. Clamp to the smallest tick.
		{name: "zero clamps to 1s", in: 0, want: "1s"},
		{name: "negative clamps to 1s", in: -time.Hour, want: "1s"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := Decision{ExpiresAt: now.Add(tt.in)}
			if got := d.RouterOSTimeout(now); got != tt.want {
				t.Errorf("RouterOSTimeout() = %q, want %q", got, tt.want)
			}
		})
	}
}
