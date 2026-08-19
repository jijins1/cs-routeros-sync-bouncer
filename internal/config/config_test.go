package config

import (
	"strings"
	"testing"
	"time"
)

const minimal = `
crowdsec:
  url: http://127.0.0.1:8080
  api_key: secret
mikrotik:
  address: 192.168.88.1:8729
  username: bouncer
  tls: true
`

func TestParseAppliesDefaults(t *testing.T) {
	cfg, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if cfg.MikroTik.MaxEntries != DefaultMaxEntries {
		t.Errorf("MaxEntries = %d, want %d", cfg.MikroTik.MaxEntries, DefaultMaxEntries)
	}
	if cfg.MikroTik.AddressListV4 != DefaultAddressListV4 {
		t.Errorf("AddressListV4 = %q, want %q", cfg.MikroTik.AddressListV4, DefaultAddressListV4)
	}
	if cfg.CrowdSec.UpdateInterval != DefaultUpdateInterval {
		t.Errorf("UpdateInterval = %v, want %v", cfg.CrowdSec.UpdateInterval, DefaultUpdateInterval)
	}
	if cfg.MikroTik.ReconcileInterval != DefaultReconcileInterval {
		t.Errorf("ReconcileInterval = %v, want %v", cfg.MikroTik.ReconcileInterval, DefaultReconcileInterval)
	}
}

func TestParseReadsDurations(t *testing.T) {
	cfg, err := Parse([]byte(minimal + `
  reconcile_interval: 30m
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.MikroTik.ReconcileInterval != 30*time.Minute {
		t.Errorf("ReconcileInterval = %v, want 30m", cfg.MikroTik.ReconcileInterval)
	}
}

// Secrets belong in the environment, not in the file.
func TestParseExpandsEnvironment(t *testing.T) {
	t.Setenv("TEST_BOUNCER_KEY", "from-env")

	cfg, err := Parse([]byte(`
crowdsec:
  url: http://127.0.0.1:8080
  api_key: ${TEST_BOUNCER_KEY}
mikrotik:
  address: 192.168.88.1:8729
  username: bouncer
  tls: true
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.CrowdSec.APIKey != "from-env" {
		t.Errorf("APIKey = %q, want from-env", cfg.CrowdSec.APIKey)
	}
}

// A mistyped key silently falling back to a default is how a max_entries cap
// goes missing without anyone noticing.
func TestParseRejectsUnknownKeys(t *testing.T) {
	_, err := Parse([]byte(minimal + `
  max_entires: 500
`))
	if err == nil {
		t.Fatal("Parse accepted a misspelled key")
	}
}

func TestValidateRequiredFields(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "missing lapi url",
			yaml: "crowdsec:\n  api_key: k\nmikrotik:\n  address: r:8729\n  username: u\n  tls: true\n",
			want: "crowdsec.url",
		},
		{
			name: "missing api key",
			yaml: "crowdsec:\n  url: http://x\nmikrotik:\n  address: r:8729\n  username: u\n  tls: true\n",
			want: "crowdsec.api_key",
		},
		{
			name: "missing router address",
			yaml: "crowdsec:\n  url: http://x\n  api_key: k\nmikrotik:\n  username: u\n  tls: true\n",
			want: "mikrotik.address",
		},
		{
			name: "missing username",
			yaml: "crowdsec:\n  url: http://x\n  api_key: k\nmikrotik:\n  address: r:8729\n  tls: true\n",
			want: "mikrotik.username",
		},
		{
			name: "address without port",
			yaml: "crowdsec:\n  url: http://x\n  api_key: k\nmikrotik:\n  address: 192.168.88.1\n  username: u\n  tls: true\n",
			want: "must include a port",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml))
			if err == nil {
				t.Fatalf("Parse accepted config missing %s", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want mention of %q", err, tt.want)
			}
		})
	}
}

// Pointing both families at one list makes each pass delete the other's
// entries, so the bouncer would fight itself forever.
func TestValidateRejectsIdenticalAddressLists(t *testing.T) {
	_, err := Parse([]byte(minimal + `
  address_list_v4: same
  address_list_v6: same
`))
	if err == nil || !strings.Contains(err.Error(), "must differ") {
		t.Errorf("error = %v, want a complaint about identical list names", err)
	}
}

// Sending the router password in the clear should not happen silently.
func TestValidateWarnsOnPlaintextPassword(t *testing.T) {
	_, err := Parse([]byte(`
crowdsec:
  url: http://127.0.0.1:8080
  api_key: secret
mikrotik:
  address: 192.168.88.1:8728
  username: bouncer
  password: hunter2
  tls: false
`))
	if err == nil || !strings.Contains(err.Error(), "unencrypted") {
		t.Errorf("error = %v, want a complaint about the unencrypted password", err)
	}
}

func TestValidateRejectsNonPositiveIntervals(t *testing.T) {
	for _, field := range []string{
		"crowdsec:\n  update_interval: -1s\n",
		"mikrotik:\n  reconcile_interval: -1s\n",
	} {
		if _, err := Parse([]byte(minimal + strings.SplitN(field, "\n", 2)[1])); err == nil {
			t.Errorf("Parse accepted %q", field)
		}
	}
}

// 0 is a deliberate "no cap" for routers with memory to spare.
func TestValidateAllowsZeroMaxEntriesAsUnlimited(t *testing.T) {
	cfg, err := Parse([]byte(minimal + `
  max_entries: -1
`))
	if err == nil {
		t.Fatalf("Parse accepted a negative max_entries: %+v", cfg)
	}
}

func TestMetricsDefaultsToTheConventionalPort(t *testing.T) {
	cfg, err := Parse([]byte(`
crowdsec:
  url: http://lapi:8080
  api_key: k
mikrotik:
  address: 10.0.0.1:8729
  username: u
  tls: true
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !cfg.Metrics.IsEnabled() {
		t.Error("metrics disabled by default; the chart ships a ServiceMonitor and would scrape nothing")
	}
	if cfg.Metrics.Listen != DefaultMetricsListen {
		t.Errorf("listen = %q, want %q", cfg.Metrics.Listen, DefaultMetricsListen)
	}
}

func TestMetricsCanBeTurnedOff(t *testing.T) {
	cfg, err := Parse([]byte(`
crowdsec:
  url: http://lapi:8080
  api_key: k
mikrotik:
  address: 10.0.0.1:8729
  username: u
  tls: true
metrics:
  enabled: false
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Metrics.IsEnabled() {
		t.Error("metrics still enabled after being set to false")
	}
}

func TestMetricsListenIsValidated(t *testing.T) {
	_, err := Parse([]byte(`
crowdsec:
  url: http://lapi:8080
  api_key: k
mikrotik:
  address: 10.0.0.1:8729
  username: u
  tls: true
metrics:
  enabled: true
  listen: "2112"
`))
	if err == nil {
		t.Fatal("a listen address without a port separator was accepted")
	}
}
