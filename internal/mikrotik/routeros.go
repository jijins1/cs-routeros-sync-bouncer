package mikrotik

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	routeros "github.com/go-routeros/routeros/v3"
)

const addressListPath = "/ip/firewall/address-list"

// Config describes how to reach the router.
type Config struct {
	Address            string // host:port, e.g. 192.168.88.1:8729
	Username           string
	Password           string
	TLS                bool
	InsecureSkipVerify bool
	Timeout            time.Duration
}

// RouterOS is a Client backed by a real device.
//
// The connection is re-established on demand: a router reboot or an idle
// timeout drops the API session, and a bouncer that gave up there would leave
// the address-list frozen with stale bans.
type RouterOS struct {
	cfg Config

	mu   sync.Mutex
	conn *routeros.Client
}

// NewRouterOS returns a client and verifies it can reach the device.
func NewRouterOS(ctx context.Context, cfg Config) (*RouterOS, error) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}

	r := &RouterOS{cfg: cfg}
	if _, err := r.client(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

// client returns a live connection, dialling if necessary. Callers must not
// hold the returned client across a reconnect.
func (r *RouterOS) client(ctx context.Context) (*routeros.Client, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.connectLocked(ctx)
}

func (r *RouterOS) connectLocked(ctx context.Context) (*routeros.Client, error) {
	if r.conn != nil {
		return r.conn, nil
	}

	dialCtx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
	defer cancel()

	var (
		conn *routeros.Client
		err  error
	)
	if r.cfg.TLS {
		conn, err = routeros.DialTLSContext(dialCtx, r.cfg.Address, r.cfg.Username, r.cfg.Password,
			&tls.Config{InsecureSkipVerify: r.cfg.InsecureSkipVerify})
	} else {
		conn, err = routeros.DialContext(dialCtx, r.cfg.Address, r.cfg.Username, r.cfg.Password)
	}
	if err != nil {
		return nil, fmt.Errorf("connect to RouterOS %s: %w", r.cfg.Address, err)
	}

	r.conn = conn
	return conn, nil
}

// reset drops the current connection so the next call redials.
func (r *RouterOS) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conn != nil {
		r.conn.Close()
		r.conn = nil
	}
}

// run executes one API sentence, retrying once on a transport failure so that
// a dropped session is repaired rather than surfaced as a sync error.
func (r *RouterOS) run(ctx context.Context, words []string) (*routeros.Reply, error) {
	conn, err := r.client(ctx)
	if err != nil {
		return nil, err
	}

	reply, err := conn.RunArgsContext(ctx, words)
	if err == nil {
		return reply, nil
	}

	// A device-level rejection (bad syntax, no such item) will fail again
	// identically; only a broken connection is worth a retry.
	var deviceErr *routeros.DeviceError
	if errors.As(err, &deviceErr) {
		return nil, err
	}

	r.reset()
	conn, cerr := r.client(ctx)
	if cerr != nil {
		return nil, fmt.Errorf("%w (reconnect failed: %v)", err, cerr)
	}
	return conn.RunArgsContext(ctx, words)
}

// List returns every entry in the named address-list.
func (r *RouterOS) List(ctx context.Context, list string) ([]Entry, error) {
	query, err := query("list", list)
	if err != nil {
		return nil, err
	}

	// ?list= filters server-side; .proplist keeps the reply small, which
	// matters when the list holds tens of thousands of rows.
	reply, err := r.run(ctx, []string{
		addressListPath + "/print",
		query,
		"=.proplist=.id,address,comment,timeout",
	})
	if err != nil {
		return nil, fmt.Errorf("list %q: %w", list, err)
	}

	entries := make([]Entry, 0, len(reply.Re))
	for _, sentence := range reply.Re {
		entries = append(entries, Entry{
			ID:      sentence.Map[".id"],
			List:    list,
			Address: sentence.Map["address"],
			Comment: sentence.Map["comment"],
			Timeout: sentence.Map["timeout"],
		})
	}
	return entries, nil
}

// Add creates one address-list entry and returns its RouterOS .id.
func (r *RouterOS) Add(ctx context.Context, e Entry) (string, error) {
	words := []string{addressListPath + "/add"}
	for _, kv := range [][2]string{
		{"list", e.List},
		{"address", e.Address},
		{"comment", e.Comment},
		{"timeout", e.Timeout},
	} {
		if kv[1] == "" {
			continue
		}
		word, err := attr(kv[0], kv[1])
		if err != nil {
			return "", err
		}
		words = append(words, word)
	}

	reply, err := r.run(ctx, words)
	if err != nil {
		return "", fmt.Errorf("add %s to %s: %w", e.Address, e.List, err)
	}
	if reply.Done != nil {
		return reply.Done.Map["ret"], nil
	}
	return "", nil
}

// Remove deletes entries by .id.
//
// RouterOS accepts a comma-separated .id list in a single call, so a large
// cleanup costs a handful of round trips rather than one per entry.
func (r *RouterOS) Remove(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}

	joined, err := attr(".id", joinIDs(ids))
	if err != nil {
		return err
	}

	if _, err := r.run(ctx, []string{addressListPath + "/remove", joined}); err != nil {
		return fmt.Errorf("remove %d entries: %w", len(ids), err)
	}
	return nil
}

// Close releases the connection.
func (r *RouterOS) Close() error {
	r.reset()
	return nil
}

func joinIDs(ids []string) string {
	return strings.Join(ids, ",")
}
