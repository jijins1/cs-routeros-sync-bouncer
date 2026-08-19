package metrics

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

// shutdownGrace bounds how long a scrape in flight may delay shutdown.
const shutdownGrace = 5 * time.Second

// Serve exposes handler on addr under /metrics until ctx is cancelled.
//
// The listener is opened before returning control, so a port already in use is
// reported as a startup error rather than surfacing much later as a silently
// absent target.
func Serve(ctx context.Context, addr string, handler http.Handler) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("metrics listen on %s: %w", addr, err)
	}
	return ServeListener(ctx, ln, handler)
}

// ServeListener is Serve on an already-open listener.
func ServeListener(ctx context.Context, ln net.Listener, handler http.Handler) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", handler)
	// A liveness target that does not depend on the registry being gatherable.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	errc := make(chan error, 1)
	go func() {
		err := srv.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errc <- err
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("metrics shutdown: %w", err)
		}
		return nil
	}
}
