package crowdsec

import (
	"testing"
	"time"
)

func TestNewBouncerMapsConfig(t *testing.T) {
	b := newBouncer(Config{
		URL:            "http://lapi:8080",
		APIKey:         "key",
		UpdateInterval: 30 * time.Second,
		UserAgent:      "cs-routeros-sync-bouncer/1.2.3",
		Origins:        []string{"crowdsec", "cscli"},
	})

	if b.APIUrl != "http://lapi:8080" {
		t.Errorf("APIUrl = %q", b.APIUrl)
	}
	if b.APIKey != "key" {
		t.Errorf("APIKey = %q", b.APIKey)
	}
	if b.TickerInterval != "30s" {
		t.Errorf("TickerInterval = %q, want 30s", b.TickerInterval)
	}
	if b.UserAgent != "cs-routeros-sync-bouncer/1.2.3" {
		t.Errorf("UserAgent = %q", b.UserAgent)
	}
	if len(b.Origins) != 2 {
		t.Errorf("Origins = %v, want both entries passed to the LAPI", b.Origins)
	}
}

// A zero interval would be sent to the SDK as "0s" and poll in a tight loop.
func TestNewBouncerDefaultsUpdateInterval(t *testing.T) {
	for _, given := range []time.Duration{0, -time.Second} {
		b := newBouncer(Config{UpdateInterval: given})
		if b.TickerInterval != defaultUpdateInterval.String() {
			t.Errorf("TickerInterval for %v = %q, want %v", given, b.TickerInterval, defaultUpdateInterval)
		}
	}
}

func TestNewBouncerDefaultsUserAgent(t *testing.T) {
	if b := newBouncer(Config{}); b.UserAgent != "cs-routeros-sync-bouncer" {
		t.Errorf("UserAgent = %q, want cs-routeros-sync-bouncer", b.UserAgent)
	}
}

// The SDK takes a pointer, so an unset field would mean "use the SDK default"
// rather than "verify certificates".
func TestNewBouncerAlwaysSetsInsecureSkipVerify(t *testing.T) {
	for _, want := range []bool{true, false} {
		b := newBouncer(Config{InsecureSkipVerify: want})
		if b.InsecureSkipVerify == nil {
			t.Fatalf("InsecureSkipVerify is nil for %v", want)
		}
		if *b.InsecureSkipVerify != want {
			t.Errorf("InsecureSkipVerify = %v, want %v", *b.InsecureSkipVerify, want)
		}
	}
}

// CrowdSec and this bouncer are usually started together, so the first
// connection attempt failing must not be fatal.
func TestNewBouncerRetriesInitialConnect(t *testing.T) {
	if b := newBouncer(Config{}); !b.RetryInitialConnect {
		t.Error("RetryInitialConnect = false, want true")
	}
}
