// Package crowdsec feeds the decision stream from a CrowdSec LAPI into the
// desired-state set.
package crowdsec

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"

	"github.com/ruokki/cs-routeros-sync-bouncer/internal/decision"
)

// banType is the only remediation a firewall address-list can express. A
// captcha or a custom remediation is somebody else's job, and enforcing it as
// a ban here would block traffic CrowdSec never asked to block.
const banType = "ban"

// Config describes the LAPI connection.
type Config struct {
	URL                string
	APIKey             string
	UpdateInterval     time.Duration
	InsecureSkipVerify bool
	UserAgent          string

	// Origins, when set, is pushed to the LAPI so unwanted blocklists are
	// never transferred in the first place.
	Origins []string
}

// Stream keeps a decision Set in step with the LAPI.
//
// The transport is held as a channel and a run function rather than as the
// concrete StreamBouncer, so the consumption loop can be driven from a test
// without a LAPI to talk to.
type Stream struct {
	decisions <-chan *models.DecisionsStreamResponse
	transport func(context.Context) error

	set *decision.Set
	log *slog.Logger

	// OnChange, when set, is called after any stream message that altered the
	// desired state. It lets the reconciler react to a new ban immediately
	// instead of waiting for its next scheduled pass.
	OnChange func()

	// primed records that the initial snapshot has been received.
	primed bool
}

// defaultUpdateInterval is used when the configuration leaves it unset.
const defaultUpdateInterval = 10 * time.Second

// newBouncer maps our configuration onto the CrowdSec SDK's. It performs no
// I/O, so the defaults it applies can be checked directly.
func newBouncer(cfg Config) *csbouncer.StreamBouncer {
	if cfg.UserAgent == "" {
		cfg.UserAgent = "cs-routeros-sync-bouncer"
	}
	if cfg.UpdateInterval <= 0 {
		cfg.UpdateInterval = defaultUpdateInterval
	}

	insecure := cfg.InsecureSkipVerify
	return &csbouncer.StreamBouncer{
		APIKey:         cfg.APIKey,
		APIUrl:         cfg.URL,
		TickerInterval: cfg.UpdateInterval.String(),
		UserAgent:      cfg.UserAgent,
		// Filtering here means an unwanted blocklist is never transferred at
		// all, rather than being downloaded and then discarded.
		Origins:            cfg.Origins,
		InsecureSkipVerify: &insecure,
		// Keep retrying if the LAPI is not up yet: on a router this process
		// and CrowdSec often start together.
		RetryInitialConnect: true,
		// Both must be set explicitly. The LAPI treats them as true when the
		// query omits them, and the client only puts them on the wire when
		// they are false - so leaving Opts at its zero value silently asks
		// for community_pull=false&additional_pull=false, cutting the bouncer
		// off from the community blocklist and any console subscription.
		Opts: apiclient.DecisionsStreamOpts{
			CommunityPull:  true,
			AdditionalPull: true,
		},
	}
}

// NewStream prepares a stream consumer and validates the LAPI connection.
func NewStream(cfg Config, set *decision.Set, log *slog.Logger) (*Stream, error) {
	if log == nil {
		log = slog.Default()
	}

	b := newBouncer(cfg)
	if err := b.Init(); err != nil {
		return nil, fmt.Errorf("initialise CrowdSec stream: %w", err)
	}

	return &Stream{
		decisions: b.Stream,
		transport: b.Run,
		set:       set,
		log:       log,
	}, nil
}

// Run consumes the decision stream until ctx is cancelled.
//
// The first message after connecting is a full snapshot of every active
// decision, so the set is rebuilt from scratch on each start and no state has
// to survive a restart.
func (s *Stream) Run(ctx context.Context) error {
	errc := make(chan error, 1)
	go func() { errc <- s.transport(ctx) }()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case err := <-errc:
			if err != nil {
				return fmt.Errorf("CrowdSec stream: %w", err)
			}
			return nil

		case resp := <-s.decisions:
			if resp == nil {
				continue
			}
			added, removed := s.Apply(resp, time.Now())
			s.log.Debug("decision stream update",
				"added", added, "removed", removed, "addresses", s.set.Len())
		}
	}
}

// Apply folds one stream message into the set, returning how many decisions
// were taken on and dropped.
//
// Deletions are processed first: when a decision is replaced by a longer one
// for the same address, handling the removal afterwards would briefly undo the
// replacement.
func (s *Stream) Apply(resp *models.DecisionsStreamResponse, now time.Time) (added, removed int) {
	for _, d := range resp.Deleted {
		if d == nil {
			continue
		}
		if s.forget(d) {
			removed++
		}
	}

	for _, d := range resp.New {
		if d == nil {
			continue
		}
		if s.remember(d, now) {
			added++
		}
	}

	// The first message is the full snapshot of every active decision, and it
	// must reach the reconciler even when it turns out to be empty: it is the
	// signal that the desired state is now trustworthy. Syncing before it
	// arrives would strip the address-list bare, since the set is still empty.
	if added+removed > 0 || !s.primed {
		s.primed = true
		if s.OnChange != nil {
			s.OnChange()
		}
	}

	return added, removed
}

func (s *Stream) forget(d *models.Decision) bool {
	if d.ID != 0 {
		return s.set.Forget(d.ID)
	}

	// No usable id: fall back to dropping the address outright. This can lift
	// a block another decision still wants, but leaving it in place would mean
	// an unban never happening, and the entry lingering on the router.
	key, _, err := decision.Canonicalize(str(d.Value))
	if err != nil {
		return false
	}
	s.log.Warn("deleted decision has no id, dropping the address wholesale", "address", key)
	return s.set.Delete(key)
}

func (s *Stream) remember(d *models.Decision, now time.Time) bool {
	if t := str(d.Type); t != "" && t != banType {
		s.log.Debug("ignoring decision, not a ban", "type", t, "value", str(d.Value))
		return false
	}

	dec, ok, err := decision.FromStream(d.ID, str(d.Scope), str(d.Value), str(d.Origin), str(d.Duration), now)
	if err != nil {
		s.log.Warn("skipping malformed decision", "error", err)
		return false
	}
	if !ok {
		return false
	}

	return s.set.Upsert(dec)
}

// str dereferences the pointer-typed fields of models.Decision, which are
// optional on the wire and nil in practice for partially-populated messages.
func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
