// Package config loads and validates the bouncer's YAML configuration.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the whole configuration file.
type Config struct {
	CrowdSec CrowdSec `yaml:"crowdsec"`
	MikroTik MikroTik `yaml:"mikrotik"`
	Origins  Origins  `yaml:"origins"`
	LogLevel string   `yaml:"log_level"`
}

// CrowdSec describes the LAPI connection.
type CrowdSec struct {
	URL                string        `yaml:"url"`
	APIKey             string        `yaml:"api_key"`
	UpdateInterval     time.Duration `yaml:"update_interval"`
	InsecureSkipVerify bool          `yaml:"insecure_skip_verify"`
}

// MikroTik describes the router and how much of it we are allowed to fill.
type MikroTik struct {
	Address            string        `yaml:"address"`
	Username           string        `yaml:"username"`
	Password           string        `yaml:"password"`
	TLS                bool          `yaml:"tls"`
	InsecureSkipVerify bool          `yaml:"insecure_skip_verify"`
	Timeout            time.Duration `yaml:"timeout"`

	AddressListV4 string `yaml:"address_list_v4"`
	AddressListV6 string `yaml:"address_list_v6"`

	// MaxEntries caps how many addresses may sit on the router at once. This
	// is the hard guard against filling its memory: a Console subscription can
	// hand out far more decisions than a small router can hold, and the excess
	// is dropped by origin priority rather than by whatever arrived last.
	MaxEntries int `yaml:"max_entries"`

	// BatchSize is how many entries are removed per API call.
	BatchSize int `yaml:"batch_size"`

	// ReconcileInterval is how often the router is re-read in full to correct
	// any drift, independently of the decision stream.
	ReconcileInterval time.Duration `yaml:"reconcile_interval"`
}

// Origins filters which decision sources are enforced.
type Origins struct {
	Include []string `yaml:"include"`
	Exclude []string `yaml:"exclude"`
}

// Defaults. MaxEntries is deliberately conservative: it applies when the
// configuration omits the field, and a router whose capacity we know nothing
// about is better served by a low cap than by an unbounded list. See the
// sizing table in the README before raising it.
const (
	DefaultUpdateInterval    = 10 * time.Second
	DefaultReconcileInterval = 5 * time.Minute
	DefaultTimeout           = 10 * time.Second
	DefaultAddressListV4     = "crowdsec-v4"
	DefaultAddressListV6     = "crowdsec-v6"
	DefaultMaxEntries        = 10000
	DefaultBatchSize         = 100
	DefaultLogLevel          = "info"
)

// Load reads, expands and validates a configuration file.
//
// Environment variables in the file are expanded, so secrets can be kept out
// of it entirely: api_key: ${CROWDSEC_BOUNCER_KEY}.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(raw)
}

// Parse expands, decodes and validates configuration bytes.
func Parse(raw []byte) (*Config, error) {
	var cfg Config

	decoder := yaml.NewDecoder(strings.NewReader(os.ExpandEnv(string(raw))))
	decoder.KnownFields(true) // a typo in a key is an error, not a silent default
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.CrowdSec.UpdateInterval == 0 {
		c.CrowdSec.UpdateInterval = DefaultUpdateInterval
	}
	if c.MikroTik.Timeout == 0 {
		c.MikroTik.Timeout = DefaultTimeout
	}
	if c.MikroTik.AddressListV4 == "" {
		c.MikroTik.AddressListV4 = DefaultAddressListV4
	}
	if c.MikroTik.AddressListV6 == "" {
		c.MikroTik.AddressListV6 = DefaultAddressListV6
	}
	if c.MikroTik.MaxEntries == 0 {
		c.MikroTik.MaxEntries = DefaultMaxEntries
	}
	if c.MikroTik.BatchSize == 0 {
		c.MikroTik.BatchSize = DefaultBatchSize
	}
	if c.MikroTik.ReconcileInterval == 0 {
		c.MikroTik.ReconcileInterval = DefaultReconcileInterval
	}
	if c.LogLevel == "" {
		c.LogLevel = DefaultLogLevel
	}
}

// Validate rejects configurations that would misbehave at runtime.
func (c *Config) Validate() error {
	var errs []error

	if c.CrowdSec.URL == "" {
		errs = append(errs, errors.New("crowdsec.url is required"))
	}
	if c.CrowdSec.APIKey == "" {
		errs = append(errs, errors.New("crowdsec.api_key is required (generate one with: cscli bouncers add cs-routeros-sync-bouncer)"))
	}
	if c.MikroTik.Address == "" {
		errs = append(errs, errors.New("mikrotik.address is required (host:port, e.g. 192.168.88.1:8729)"))
	} else if !strings.Contains(c.MikroTik.Address, ":") {
		errs = append(errs, fmt.Errorf("mikrotik.address %q must include a port (8728 plain, 8729 TLS)", c.MikroTik.Address))
	}
	if c.MikroTik.Username == "" {
		errs = append(errs, errors.New("mikrotik.username is required"))
	}

	// Both lists sharing a name would make each family's reconciliation delete
	// the other's entries, in a loop.
	if c.MikroTik.AddressListV4 == c.MikroTik.AddressListV6 {
		errs = append(errs, fmt.Errorf("mikrotik.address_list_v4 and address_list_v6 must differ (both are %q)", c.MikroTik.AddressListV4))
	}

	if c.MikroTik.MaxEntries < 0 {
		errs = append(errs, errors.New("mikrotik.max_entries cannot be negative (0 disables the cap)"))
	}
	if c.MikroTik.BatchSize <= 0 {
		errs = append(errs, errors.New("mikrotik.batch_size must be positive"))
	}
	if c.CrowdSec.UpdateInterval <= 0 {
		errs = append(errs, errors.New("crowdsec.update_interval must be positive"))
	}
	if c.MikroTik.ReconcileInterval <= 0 {
		errs = append(errs, errors.New("mikrotik.reconcile_interval must be positive"))
	}

	if !c.MikroTik.TLS && c.MikroTik.Password != "" {
		// Not fatal, but the API password crosses the wire in the clear.
		errs = append(errs, errors.New("mikrotik.tls is disabled: the RouterOS API password would be sent unencrypted; set tls: true (port 8729) or acknowledge by using an empty password"))
	}

	return errors.Join(errs...)
}
