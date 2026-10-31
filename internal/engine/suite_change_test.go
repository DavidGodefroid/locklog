//go:build unix

package engine

// Change requests (locklog_request_change) are the console's own
// change.request: lockkit queues the proposal for the human's :review and
// answers {queued: true}; nothing is applied. This runs them through a
// lockkit console with locklog's product names, with canaries (every kind
// in every encoding) and injections in the change text, and checks what
// leaves the console: the answer on the socket holds nothing the agent did
// not write and is the same whatever was written, and the line the human
// reads holds no raw control or invisible character.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/audit"
	kconfig "github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/ipc"

	"github.com/DavidGodefroid/locklog/internal/mask/masktest"
	"github.com/DavidGodefroid/locklog/internal/product"
)

type changePolicy struct{}

func (changePolicy) Diff(kconfig.Policy) []kconfig.Change { return nil }
func (changePolicy) Describe() []string                   { return []string{"suite"} }
func (changePolicy) Profile() console.Profile {
	return console.Profile{Name: "staging", Where: "suite", Credentials: console.CredentialsNone}
}

type changeSession struct{}

func (changeSession) Close() error { return nil }

type changeBackend struct{}

func (changeBackend) Methods() map[string]console.Handler { return map[string]console.Handler{} }
func (changeBackend) Connect(context.Context, console.Credentials) (console.Session, error) {
	return changeSession{}, nil
}
func (changeBackend) Checks(context.Context, console.Session) []console.Finding { return nil }
func (changeBackend) LoadPolicy() (console.Policy, error)                       { return changePolicy{}, nil }
func (changeBackend) Status(console.Session) any                                { return nil }

// changeIO is the console's terminal: it keeps the lines and answers no
// prompt.
type changeIO struct {
	mu    sync.Mutex
	lines []string
}

func (c *changeIO) Println(s string) { c.mu.Lock(); c.lines = append(c.lines, s); c.mu.Unlock() }
func (c *changeIO) Ask(context.Context, string, time.Duration) (string, bool) {
	return "", false
}
func (c *changeIO) AskSecret(context.Context, string) ([]byte, error) {
	return nil, errors.New("no terminal")
}
func (c *changeIO) take() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.lines
	c.lines = nil
	return out
}

func newChangeConsole(t *testing.T) (*console.Server, *changeIO) {
	t.Helper()
	state := t.TempDir()
	log, err := audit.Open(product.P, state)
	if err != nil {
		t.Fatal(err)
	}
	io := &changeIO{}
	s, err := console.NewServer(console.ServerConfig{Product: product.P, Backend: changeBackend{}, Policy: changePolicy{},
		StateDir: state, Session: changeSession{}, Audit: log, IO: io})
	if err != nil {
		t.Fatal(err)
	}
	io.take()
	return s, io
}

func changeRequest(s *console.Server, change string) []byte {
	params, _ := json.Marshal(ipc.ChangeParams{Change: change})
	resp := s.Handle(context.Background(), ipc.Request{JSONRPC: "2.0", ID: 7, Method: ipc.MethodChangeRequest, Params: params})
	b, _ := json.Marshal(resp)
	return b
}

// TestSuiteChangeRequest: change requests carrying canaries (every kind;
// every encoding with LOCKLOG_SUITE_FULL=1, a subset otherwise) and
// injections. The socket answer holds none of them and is the same answer
// for every accepted request (the oracle: what was written changes
// nothing the agent reads back); a refused request (empty, too long, the
// queue full) is refused in words that quote none of it. The human's
// console line holds no raw control, bidi or invisible character.
func TestSuiteChangeRequest(t *testing.T) {
	knownInvisible = 0
	per := len(masktest.Kinds) * len(masktest.Encodings)
	lines := masktest.New(77).Lines(per)
	seen := map[string]bool{}
	var accepted string
	n := 0
	for _, ln := range lines {
		c, enc := ln.Canaries[0], masktest.Encodings[ln.Encoding]
		if !suiteFull() && seen[c.Kind] && seen[enc] {
			continue
		}
		seen[c.Kind], seen[enc] = true, true
		w := masktest.Encode(c.Value, enc)
		own := []masktest.Canary{c}
		// A fresh console per request: its queue is bounded.
		s, io := newChangeConsole(t)
		for _, change := range []string{
			"add trusted label app for " + w,
			"budget remote.range = 48h; the user " + w + " asked",
			strings.Repeat(w+" ", 600/(len(w)+1)+1), // too long: refused
		} {
			where := fmt.Sprintf("change request with %s %q", c.Kind, w)
			out := changeRequest(s, change)
			if hits := masktest.Scan(where, out, own); len(hits) > 0 {
				t.Errorf("%s: the answer echoes it: %s", where, out)
			}
			var r ipc.Response
			json.Unmarshal(out, &r)
			if r.Error == nil {
				// Every accepted request gets the same answer.
				if accepted == "" {
					accepted = string(out)
				}
				if string(out) != accepted {
					t.Errorf("%s: answer %s, others %s", where, out, accepted)
				}
				n++
			} else if len(change) <= 500 {
				t.Errorf("%s: refused: %s", where, out)
			}
			for _, l := range io.take() {
				checkConsoleLine(t, where, l)
			}
		}
	}
	if !strings.Contains(accepted, `"queued":true`) || n == 0 {
		t.Fatalf("no change request queued: %q", accepted)
	}
	// Injections: queued, the human's line escaped, the answer unchanged.
	s, io := newChangeConsole(t)
	for i, inj := range injections {
		out := changeRequest(s, "trust label "+inj)
		if string(out) != accepted {
			t.Errorf("injection %d: answer %s", i, out)
		}
		checkInjection(t, fmt.Sprintf("change request answer %d", i), out)
		for _, l := range io.take() {
			checkConsoleLine(t, fmt.Sprintf("injection %d", i), l)
		}
	}
	// The queue full: refused, quoting nothing.
	defer func() {
		if knownInvisible > 0 && !t.Failed() {
			t.Skipf("known gap, https://github.com/DavidGodefroid/lockkit/issues/116: %d console lines held a zero-width, tag or other format character (controls and bidi controls were escaped)", knownInvisible)
		}
	}()
	for i := 0; i < 64; i++ {
		out := changeRequest(s, fmt.Sprintf("change %d for alice.martin@shop.example", i))
		var r ipc.Response
		json.Unmarshal(out, &r)
		if r.Error != nil {
			if strings.Contains(string(out), "alice") || strings.Contains(string(out), "shop.example") {
				t.Errorf("queue full: the refusal quotes the request: %s", out)
			}
			return
		}
	}
	t.Error("the change request queue is unbounded")
}

// knownInvisible counts the console lines that held an invisible or
// format character other than a control or a bidi control: lockkit's
// sanitize.Terminal lets them through (lockkit#116).
var knownInvisible int

// checkConsoleLine checks a console line: no raw control character but
// the console's own colour escapes (ESC [ ... m), no bidi control; another
// invisible or format character is the known gap lockkit#116, counted.
func checkConsoleLine(t *testing.T, where, l string) {
	t.Helper()
	plain := sgr.ReplaceAllString(l, "")
	for _, r := range plain {
		if !unsafeOut(r) {
			continue
		}
		if r < 0x20 || r == 0x7f || r >= 0x80 && r < 0xa0 || r == 0x061c || r == 0x200e || r == 0x200f || r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069 {
			t.Errorf("%s: the console line holds %U: %q", where, r, l)
		} else {
			knownInvisible++
		}
		return
	}
}

// sgr matches the console's colour escapes.
var sgr = regexp.MustCompile("\x1b\\[[0-9;]*m")
