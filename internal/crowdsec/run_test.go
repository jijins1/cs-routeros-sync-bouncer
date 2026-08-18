package crowdsec

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"

	"github.com/ruokki/cs-routeros-sync-bouncer/internal/decision"
)

// runnableStream wires a Stream to a channel the test controls.
func runnableStream(transport func(context.Context) error) (*Stream, chan *models.DecisionsStreamResponse, *decision.Set) {
	ch := make(chan *models.DecisionsStreamResponse, 4)
	set := decision.NewSet(0, decision.OriginFilter{})

	if transport == nil {
		// Stand in for a healthy connection: stays up until cancelled.
		transport = func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		}
	}

	return &Stream{
		decisions: ch,
		transport: transport,
		set:       set,
		log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, ch, set
}

func TestRunAppliesIncomingMessages(t *testing.T) {
	s, ch, set := runnableStream(nil)

	applied := make(chan struct{}, 1)
	s.OnChange = func() {
		select {
		case applied <- struct{}{}:
		default:
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	ch <- &models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{dec(1, "Ip", "1.2.3.4", "crowdsec", "4h", "ban")},
	}

	select {
	case <-applied:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the message to be applied")
	}

	if got := set.Snapshot(time.Now()); len(got) != 1 {
		t.Errorf("set holds %d addresses, want 1", len(got))
	}

	cancel()
	<-done
}

func TestRunStopsOnContextCancellation(t *testing.T) {
	s, _, _ := runnableStream(nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}

// A transport that gives up must surface, not leave the bouncer sitting idle
// while the router quietly goes stale.
func TestRunReportsTransportFailure(t *testing.T) {
	boom := errors.New("lapi unreachable")
	s, _, _ := runnableStream(func(context.Context) error { return boom })

	done := make(chan error, 1)
	go func() { done <- s.Run(context.Background()) }()

	select {
	case err := <-done:
		if !errors.Is(err, boom) {
			t.Errorf("Run returned %v, want it to wrap %v", err, boom)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after the transport failed")
	}
}

func TestRunReturnsWhenTransportFinishes(t *testing.T) {
	s, _, _ := runnableStream(func(context.Context) error { return nil })

	done := make(chan error, 1)
	go func() { done <- s.Run(context.Background()) }()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return")
	}
}

// The channel can yield a nil message; dereferencing it would take the
// process down and stop every ban.
func TestRunIgnoresNilMessages(t *testing.T) {
	s, ch, _ := runnableStream(nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	ch <- nil

	applied := make(chan struct{}, 1)
	s.OnChange = func() {
		select {
		case applied <- struct{}{}:
		default:
		}
	}
	ch <- &models.DecisionsStreamResponse{
		New: models.GetDecisionsResponse{dec(1, "Ip", "1.2.3.4", "crowdsec", "4h", "ban")},
	}

	select {
	case <-applied:
	case <-time.After(2 * time.Second):
		t.Fatal("Run stopped processing after a nil message")
	}

	cancel()
	<-done
}
