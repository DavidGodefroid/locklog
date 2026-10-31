package session

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"sync"
	"time"

	"github.com/DavidGodefroid/locklog/internal/config"
	"github.com/DavidGodefroid/locklog/internal/egress"
	"github.com/DavidGodefroid/locklog/internal/parse"
	"github.com/DavidGodefroid/locklog/internal/source"
	"github.com/DavidGodefroid/locklog/internal/source/elastic"
	"github.com/DavidGodefroid/locklog/internal/source/loki"
)

// openRemote opens a Loki, Elasticsearch or OpenSearch source: its egress
// client (the source's allowlist, the credentials the console obtained,
// its tls mode), its parser, and the connection checks (design §2.5,
// §2.6, LL13).
//
// At connection, on a production profile:
//   - the unauthenticated-read probe: a data read without credentials
//     that answers refuses the profile;
//   - for Elasticsearch / OpenSearch, elastic.Source.Check: the backend's
//     flavour, a read-only key, the trusted fields' mappings. A failure
//     refuses the profile.
//
// Off production, Check runs too; a failure is noted on :status (no
// detail) and the source stays open, failing closed: until a Check
// succeeds it pushes no trusted term to the server and serves no count
// there (its terms are matched locally, its counts scanned).
//
// Re-Check policy (#93): one Check, here, before the source is handed to
// the engine. Nothing plans, scans, counts or describes the source before
// it returns, so on production no request but the checks' reaches the
// backend before Check has succeeded. A reconnection opens a new session,
// which checks again; there is no timer.
//
// The errors name the source and the check that failed, never a
// credential or a response body (the egress client and the source quote
// neither).
func (s *Session) openRemote(ctx context.Context, c config.Source, o Options) (source.Source, error) {
	r := c.Remote
	if r == nil {
		return nil, errors.New("a remote source without its connection settings")
	}
	prod := o.Policy.Profile.Production
	p, err := parse.New(parse.Options{Format: c.Format, Multiline: c.Multiline})
	if err != nil {
		return nil, err
	}
	// The console obtains one secret per profile, for the remote source
	// with credentials (logconsole.Backend.LoadPolicy allows one); a
	// source without credentials sends none.
	var creds egress.Credentials
	if r.Credentials != "" {
		creds = o.Credentials
		if r.User != "" {
			creds.User = r.User
		}
	}
	eo := o.Egress
	switch c.Kind {
	case config.KindLoki:
		eo.Headers = maps.Clone(egress.LokiHeaders)
		cl, err := egress.New(r, egress.LokiRoutes, creds, eo)
		if err != nil {
			return nil, err
		}
		if err := egress.CheckUnauthenticated(ctx, cl, prod); err != nil {
			return nil, refused(err)
		}
		return loki.New(loki.Options{Name: c.Name, Client: cl, Parser: p, Selector: r.Selector,
			TrustedLabels: r.TrustedLabels, TrustedMetadata: r.TrustedMetadata, Now: o.Now})
	case config.KindElastic, config.KindOpenSearch:
		routes, err := egress.ElasticRoutes(r.Indices)
		if err != nil {
			return nil, err
		}
		cl, err := egress.New(r, routes, creds, eo)
		if err != nil {
			return nil, err
		}
		if err := egress.CheckElasticUnauthenticated(ctx, cl, prod, r.Indices); err != nil {
			return nil, refused(err)
		}
		kind := elastic.KindElastic
		if c.Kind == config.KindOpenSearch {
			kind = elastic.KindOpenSearch
		}
		src, err := elastic.New(elastic.Options{Name: c.Name, Kind: kind, Client: cl, Parser: p, Indices: r.Indices,
			Selector: r.Selector, TrustedFields: r.TrustedFields, TimeField: r.TimeField, MessageField: r.MessageField,
			TieBreaker: r.TieBreaker, ReadOnlyRoles: r.ReadOnlyRoles, Now: o.Now})
		if err != nil {
			return nil, err
		}
		if _, err := src.Check(ctx, prod); err != nil {
			if prod {
				return nil, refused(err)
			}
			s.notes = append(s.notes, fmt.Sprintf("source %s: the backend check (privileges, field mappings) failed: its trusted terms are matched locally and its counts scanned (reconnect to check again)", c.Name))
		}
		return src, nil
	}
	return nil, fmt.Errorf("unsupported source kind %q", c.Kind)
}

// refused is the refusal of a profile by a connection check.
func refused(err error) error {
	return fmt.Errorf("the connection checks refuse this profile: %w", err)
}

// rateLimiter paces the remote requests of the agent's calls, the
// rolling budget limits.remote.requests_per_minute: a token bucket that
// refills perMinute tokens a minute and holds at most a minute of them.
// It implements source.Limiter.
type rateLimiter struct {
	mu     sync.Mutex
	rate   float64 // tokens per second
	burst  float64
	tokens float64
	last   time.Time
	now    func() time.Time
}

func newRateLimiter(perMinute int, now func() time.Time) *rateLimiter {
	if perMinute <= 0 {
		return nil
	}
	if now == nil {
		now = time.Now
	}
	burst := float64(perMinute)
	return &rateLimiter{rate: float64(perMinute) / 60, burst: burst, tokens: burst, now: now}
}

// Wait implements source.Limiter.
func (l *rateLimiter) Wait(ctx context.Context) error {
	for {
		l.mu.Lock()
		now := l.now()
		if !l.last.IsZero() && now.After(l.last) {
			l.tokens = min(l.burst, l.tokens+now.Sub(l.last).Seconds()*l.rate)
		}
		if l.last.IsZero() || now.After(l.last) {
			l.last = now
		}
		if l.tokens >= 1 {
			l.tokens--
			l.mu.Unlock()
			return nil
		}
		wait := time.Duration((1 - l.tokens) / l.rate * float64(time.Second))
		l.mu.Unlock()
		t := time.NewTimer(max(wait, time.Millisecond))
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}
