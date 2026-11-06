//go:build unix

package hub

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/DavidGodefroid/lockkit/ipc"
	"github.com/DavidGodefroid/lockkit/pii"
	"github.com/DavidGodefroid/lockkit/plans"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/locklog/internal/mask/masktest"
	"github.com/DavidGodefroid/locklog/internal/mcptools"
)

// The leak harness over the bytes leaving the console (design §4.7, #86):
// the masktest corpus (every detector kind in every position and encoding)
// is served by a hub-attached console, and every byte it sends out is
// scanned for every form of every canary (raw, lower case, percent- and
// JSON-escaped, decoded): the IPC socket's replies, the audit file, the
// MCP tools' outputs (text and structured) and the screens of the tickets
// it pushes to the hub. Calls carry canaries too (an agent writing a
// personal value): none comes back. 0 hits.

// leakCfg serves the corpus, one file source per format, with every
// detector of the corpus kinds.
const leakCfg = `version = 1
[profiles.staging]
structured = "MODE"
detectors = DETECTORS
EXTRA
[profiles.staging.sources.json]
kind = "file"
format = "json"
paths = ["LOGS/json.log"]
trusted = ["level", "status"]
[profiles.staging.sources.logfmt]
kind = "file"
format = "logfmt"
paths = ["LOGS/logfmt.log"]
trusted = ["level"]
[profiles.staging.sources.plain]
kind = "file"
format = "plain"
paths = ["LOGS/plain.log"]
`

// leakFrom and leakTo cover the corpus (masktest stamps 14:00 to 14:59).
const (
	leakFrom = "2026-10-30T13:00:00Z"
	leakTo   = "2026-10-30T16:00:00Z"
)

// sockConn is a console connection over the console's real Unix socket:
// it keeps every byte the console sent back.
type sockConn struct {
	mu   sync.Mutex
	c    net.Conn
	r    *bufio.Reader
	got  bytes.Buffer
	next int64
}

func dialSock(t *testing.T, path string) *sockConn {
	t.Helper()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	s := &sockConn{c: c}
	s.r = bufio.NewReader(io.TeeReader(c, &s.got))
	t.Cleanup(func() { c.Close() })
	return s
}

func (s *sockConn) Call(ctx context.Context, method string, params, result any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var raw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return err
		}
		raw = b
	}
	s.next++
	if err := ipc.WriteMsg(s.c, ipc.Request{JSONRPC: "2.0", ID: s.next, Method: method, Params: raw}); err != nil {
		return err
	}
	var resp ipc.Response
	if err := ipc.ReadMsg(s.r, &resp); err != nil {
		return err
	}
	if resp.Error != nil {
		return resp.Error
	}
	if result == nil {
		return nil
	}
	return json.Unmarshal(resp.Result, result)
}

func (s *sockConn) Close() error { return nil }

func (s *sockConn) bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Clone(s.got.Bytes())
}

// serveSocket serves the rig's console on a real Unix socket (its request
// loop, as console.Run does) and returns its path.
func (r *rig) serveSocket() string {
	r.t.Helper()
	// A short path: a Unix socket's is at most 108 bytes.
	dir, err := os.MkdirTemp("", "ll")
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "s")
	ln, err := net.Listen("unix", path)
	if err != nil {
		r.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.srv.Loop().Serve(ctx, ln, nil) }()
	r.t.Cleanup(func() { cancel(); <-done })
	return path
}

// mcpOver connects an MCP client to the tools over conn.
func (r *rig) mcpOver(conn mcptools.Conn, tok string) *mcp.ClientSession {
	r.t.Helper()
	srv := mcptools.New(mcptools.Options{Profiles: func() ([]string, error) { return []string{"staging"}, nil },
		Dial: func(string) (mcptools.Conn, error) { return conn, nil }, Version: "test",
		Requester: ipc.Requester{Agent: "dev-1", Token: plans.HashToken(tok)}})
	ctx := context.Background()
	st, ct := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		r.t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { cs.Close(); ss.Close() })
	return cs
}

// leakScanner looks for every form of every canary in a text, once: the
// forms are indexed by their first gramLen bytes, lower case.
type leakScanner struct {
	forms []leakForm
	grams map[string][]int
	short []int
	words map[string]*regexp.Regexp
}

type leakForm struct {
	c    masktest.Canary
	form string
}

const gramLen = 6

func newLeakScanner(cs []masktest.Canary) *leakScanner {
	l := &leakScanner{grams: map[string][]int{}, words: map[string]*regexp.Regexp{}}
	seen := map[string]bool{}
	for _, c := range cs {
		for _, f := range masktest.Forms(c) {
			f = strings.ToLower(f)
			if f == "" || seen[f] {
				continue
			}
			seen[f] = true
			l.forms = append(l.forms, leakForm{c, f})
			if len(f) < gramLen {
				l.short = append(l.short, len(l.forms)-1)
			} else {
				l.grams[f[:gramLen]] = append(l.grams[f[:gramLen]], len(l.forms)-1)
			}
		}
		for _, w := range masktest.WordForms(c) {
			if l.words[w] == nil {
				l.words[w] = regexp.MustCompile(`(?i)(?:^|[^\p{L}\p{N}_])` + regexp.QuoteMeta(w) + `(?:$|[^\p{L}\p{N}_])`)
			}
		}
	}
	return l
}

// Opaque values blanked before a scan: AEAD-sealed refs and cursors,
// well-formed pseudonyms, digests and hashes, ticket ids. They are not log
// content, and over many kilobytes their random letters and digits would
// match the short canary forms (digit runs, a secret's head) by chance.
var opaque = []*regexp.Regexp{
	regexp.MustCompile(`(\\?")(ref|cursor)(\\?"):\s*(\\?")[^"\\]*(\\?")`),
	regexp.MustCompile(`⟦[a-z_]+:[A-Z0-9]+⟧`),
}

// views are the texts a canary is looked for in, as masktest.Scan reads
// them: raw, decoded twice, without replacement characters; lower case.
func views(s string) []string {
	texts := []string{s}
	for _, v := range pii.DetectionViews(s) {
		for _, w := range pii.DetectionViews(v.Text) {
			texts = append(texts, w.Text, strings.ReplaceAll(w.Text, "�", ""))
		}
	}
	for i := range texts {
		texts[i] = strings.ToLower(texts[i])
	}
	return texts
}

// scan returns every canary form found in out.
func (l *leakScanner) scan(where string, out []byte) []masktest.Hit {
	s := string(out)
	for _, re := range opaque {
		s = re.ReplaceAllString(s, "#")
	}
	var hits []masktest.Hit
	found := map[int]bool{}
	hit := func(fi int) {
		if !found[fi] {
			found[fi] = true
			hits = append(hits, masktest.Hit{Canary: l.forms[fi].c, Form: l.forms[fi].form, Where: where})
		}
	}
	vs := views(s)
	for _, v := range vs {
		for i := 0; i+gramLen <= len(v); i++ {
			for _, fi := range l.grams[v[i:i+gramLen]] {
				if strings.HasPrefix(v[i:], l.forms[fi].form) {
					hit(fi)
				}
			}
		}
		for _, fi := range l.short {
			if strings.Contains(v, l.forms[fi].form) {
				hit(fi)
			}
		}
	}
	for w, re := range l.words {
		for _, v := range vs {
			if re.MatchString(v) {
				hits = append(hits, masktest.Hit{Canary: masktest.Canary{Kind: "person_name", Value: w}, Form: w, Where: where})
				break
			}
		}
	}
	return hits
}

// leakCorpus is the corpus: every (kind, encoding, position) once, by
// format.
func leakCorpus() (map[string]string, []masktest.Canary) {
	n := len(masktest.Kinds) * len(masktest.Encodings) * masktest.Positions
	files := map[string]*strings.Builder{}
	var cs []masktest.Canary
	for _, l := range masktest.New(86).Lines(n) {
		b := files[l.Format]
		if b == nil {
			b = &strings.Builder{}
			files[l.Format] = b
		}
		b.WriteString(l.Text + "\n")
		cs = append(cs, l.Canaries...)
	}
	out := map[string]string{}
	for f, b := range files {
		out[f+".log"] = b.String()
	}
	return out, cs
}

// agentCanaries are values an agent writes into its calls: every kind raw,
// and every kind and every encoding once.
func agentCanaries() (written []string, cs []masktest.Canary) {
	per := len(masktest.Kinds) * len(masktest.Encodings)
	seen := map[string]bool{}
	for _, l := range masktest.New(99).Lines(per) {
		c, enc := l.Canaries[0], masktest.Encodings[l.Encoding]
		if !seen["raw "+c.Kind] {
			seen["raw "+c.Kind] = true
			written, cs = append(written, c.Value), append(cs, c)
		}
		if !seen["kind "+c.Kind] || !seen["encoding "+enc] {
			seen["kind "+c.Kind], seen["encoding "+enc] = true, true
			written, cs = append(written, masktest.Encode(c.Value, enc)), append(cs, c)
		}
	}
	return written, cs
}

// TestLeakScannerFires is the harness's positive control: every canary of
// the corpus is found in its raw line, also once the line is JSON-encoded
// (as the socket carries it) and under a key the blanking does not touch.
func TestLeakScannerFires(t *testing.T) {
	n := len(masktest.Kinds) * len(masktest.Encodings) * masktest.Positions
	lines := masktest.New(86).Lines(n)
	var cs []masktest.Canary
	for _, l := range lines {
		cs = append(cs, l.Canaries...)
	}
	l := newLeakScanner(cs)
	missed := 0
	for _, ln := range lines {
		c := ln.Canaries[0]
		enc, _ := json.Marshal(map[string]any{"result": map[string]string{"msg": ln.Text}})
		for _, out := range [][]byte{[]byte(ln.Text), enc} {
			ok := false
			for _, h := range l.scan("control", out) {
				if h.Canary.Value == c.Value || h.Canary.Kind == "person_name" && c.Kind == "person_name" {
					ok = true
				}
			}
			if !ok {
				missed++
				t.Errorf("%s %q not found in %.200q", c.Kind, c.Value, out)
				break
			}
		}
	}
	if missed > 0 {
		t.Fatalf("%d canaries the harness cannot see", missed)
	}
}

// TestLeakHarnessConsoleBytes: the corpus through the hub-attached console
// and the MCP tools; the socket's bytes, the audit file, the MCP outputs
// and the hub tickets' screens hold no form of any canary.
func TestLeakHarnessConsoleBytes(t *testing.T) {
	files, corpus := leakCorpus()
	written, agent := agentCanaries()
	scanner := newLeakScanner(append(corpus, agent...))
	detectors, _ := json.Marshal(masktest.ValueDetectors)
	modes := []string{"detect", "redact-unknown"}
	if testing.Short() {
		modes = modes[:1] // the race job
	}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			conf := strings.NewReplacer("MODE", mode, "DETECTORS", string(detectors)).Replace(leakCfg)
			r := newRig(t, rigOpts{cfg: conf, files: files, rules: masktest.RulesForCorpus,
				now: time.Date(2026, 10, 30, 16, 0, 0, 0, time.UTC)})
			sock := dialSock(t, r.serveSocket())
			r.cs = r.mcpOver(sock, r.token)
			leakCalls(t, r, written)
			var hits []masktest.Hit
			hits = append(hits, scanner.scan("socket", sock.bytes())...)
			hits = append(hits, scanner.scan("audit", []byte(auditChainBlanked(r.auditLog())))...)
			r.mu.Lock()
			outputs := slices.Clone(r.outputs)
			r.mu.Unlock()
			for i, o := range outputs {
				hits = append(hits, scanner.scan(fmt.Sprintf("MCP output %d", i), []byte(o))...)
			}
			n := len(outputs)
			screens := 0
			for _, tk := range r.hub.Tickets() {
				signed, err := ticket.VerifyTicket(r.pub, r.hub.Ticket(tk))
				if err != nil {
					t.Fatal(err)
				}
				b, _ := json.Marshal(signed.Screen)
				hits = append(hits, scanner.scan("hub screen of "+tk, b)...)
				screens++
			}
			for i, h := range hits {
				if i >= 20 {
					break
				}
				t.Errorf("%s %q leaked as %q in %s", h.Canary.Kind, h.Canary.Value, h.Form, h.Where)
				var k int
				if _, err := fmt.Sscanf(h.Where, "MCP output %d", &k); err == nil {
					t.Logf("output %d: %.600s", k, outputs[k])
				}
			}
			if len(hits) > 0 {
				t.Fatalf("%d leaks", len(hits))
			}
			if len(sock.bytes()) < 100_000 || n < 50 || screens < 2 {
				t.Fatalf("the harness saw too little: %d socket bytes, %d MCP outputs, %d hub screens", len(sock.bytes()), n, screens)
			}
			t.Logf("%d socket bytes, %d MCP outputs, %d hub screens, %d audit bytes: 0 hits", len(sock.bytes()), n, screens, len(r.auditLog()))
		})
	}
}

// leakCalls makes the agent's calls: every tool over the corpus (search
// continued through its cursors), the approved tools' pending answers and
// decisions in hub mode, and calls carrying the written canaries where an
// agent may write anything.
func leakCalls(t *testing.T, r *rig, written []string) {
	t.Helper()
	with := func(kv ...any) map[string]any {
		m := map[string]any{"from": leakFrom, "to": leakTo}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		return m
	}
	r.call(mcptools.ToolStatus, nil)
	r.call(mcptools.ToolSources, nil)
	// Every record, every page.
	var refs []string
	var pseudo, pseudoRef string
	args := with("limit", 200)
	for page := 0; ; page++ {
		a := r.call(mcptools.ToolSearch, args)
		var res struct {
			Records  []map[string]any `json:"records"`
			Cursor   string           `json:"cursor"`
			Complete bool             `json:"complete"`
		}
		if err := json.Unmarshal(a.out.Data, &res); err != nil {
			t.Fatalf("search page %d: %v %s", page, err, a.text)
		}
		for _, rec := range res.Records {
			ref, ok := rec["ref"].(string)
			if !ok {
				continue
			}
			refs = append(refs, ref)
			if pseudo == "" {
				b, _ := json.Marshal(rec)
				if m := tokenAny.FindString(string(b)); m != "" {
					pseudo, pseudoRef = m, ref
				}
			}
		}
		if res.Complete || res.Cursor == "" || page > 50 {
			break
		}
		args = with("limit", 200, "cursor", res.Cursor)
	}
	if len(refs) < 500 {
		t.Fatalf("search returned %d records", len(refs))
	}
	r.call(mcptools.ToolCount, with("by", []string{"level"}, "bucket", "1m", "first_last", true))
	r.call(mcptools.ToolCount, with("by", []string{"level"}, "by_pattern", true))
	r.call(mcptools.ToolPatterns, with("top", 100))
	r.call(mcptools.ToolPatterns, with("top", 100, "baseline", "24h"))
	r.call(mcptools.ToolTrace, map[string]any{"id": "4812", "from": leakFrom, "to": leakTo, "limit": 200})
	r.call(mcptools.ToolTail, map[string]any{"duration": "1s", "max": 5})
	for _, ref := range []string{refs[0], refs[len(refs)/2], refs[len(refs)-1]} {
		r.call(mcptools.ToolContext, map[string]any{"ref": ref, "before": 50, "after": 50})
	}
	r.call(mcptools.ToolPIIList, nil)

	// Hub mode: a scan goes to the hub as a ticket; its pending answer,
	// then its approved run.
	scan := map[string]any{"tool": "search", "query": with("limit", 200), "reason": "the incident of " + written[0]}
	tk := r.mustPending(r.call(mcptools.ToolScan, scan))
	r.hub.Decide(tk, ticket.Approved, "")
	scan["ticket"] = tk
	r.decided(mcptools.ToolScan, scan)
	// An unmask: pending, then denied.
	if pseudo == "" {
		t.Fatal("no pseudonym in any record")
	}
	um := map[string]any{"ref": pseudoRef, "pseudonyms": []string{pseudo}, "reason": "who is " + written[1]}
	tk = r.mustPending(r.call(mcptools.ToolUnmask, um))
	r.hub.Decide(tk, ticket.Denied, "not now")
	um["ticket"] = tk
	r.decided(mcptools.ToolUnmask, um)

	// The written canaries, where an agent may write anything: refusals
	// and answers alike hold none of them.
	for _, w := range written {
		r.call(mcptools.ToolSearch, with("text", w, "limit", 5))
		r.call(mcptools.ToolSearch, with("regex", regexp.QuoteMeta(w), "limit", 5))
		r.call(mcptools.ToolSearch, with("where", []map[string]any{{"field": "detail", "op": "=", "value": w}}))
		r.call(mcptools.ToolSearch, with("where", []map[string]any{{"field": w, "op": "exists"}}))
		r.call(mcptools.ToolSearch, with("sources", []string{w}))
		r.call(mcptools.ToolSearch, with("cursor", w))
		r.call(mcptools.ToolCount, with("by", []string{w}))
		r.call(mcptools.ToolPatterns, with("baseline", w))
		r.call(mcptools.ToolTrace, map[string]any{"id": w, "from": leakFrom, "to": leakTo})
		r.call(mcptools.ToolContext, map[string]any{"ref": w})
		r.call(mcptools.ToolLookup, map[string]any{"kind": "email", "values": []string{w}, "reason": w})
		r.call(mcptools.ToolPIIAdd, map[string]any{"pattern": w})
		r.call(mcptools.ToolRequestChange, map[string]any{"change": "add the source " + w})
	}
}

var tokenAny = regexp.MustCompile(`⟦(email|phone|iban|card|ip|person_name)[a-z_]*:[A-Z0-9]+⟧`)

// auditChain is the audit's hash chain: each record's `prev_hash`, the
// SHA-256 of the record before it. Its hex digits are random, and a run of
// seven of them can equal the partial form of a numeric canary (the last
// digits of a card or an IBAN), a false hit; the chain carries nothing of
// a record's content but its hash.
var auditChain = regexp.MustCompile(`"prev_hash":"sha256:[0-9a-f]{64}"`)

// auditChainBlanked is the audit with its hash chain blanked, every other
// byte scanned as written.
func auditChainBlanked(a string) string {
	return auditChain.ReplaceAllString(a, `"prev_hash":"sha256:-"`)
}
