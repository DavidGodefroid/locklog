package mcptools

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/DavidGodefroid/lockkit/client"
	"github.com/DavidGodefroid/lockkit/ipc"
	"github.com/DavidGodefroid/lockkit/refusal"

	"github.com/DavidGodefroid/locklog/internal/logconsole"
)

type fakeConn struct {
	mu         sync.Mutex
	calls      []string
	production bool
	status     []byte // replaces the status answer when set
	err        error
}

func (f *fakeConn) Call(_ context.Context, method string, params, result any) error {
	raw, _ := json.Marshal(params)
	f.mu.Lock()
	f.calls = append(f.calls, method+" "+string(raw))
	f.mu.Unlock()
	if method == ipc.MethodStatus {
		b := []byte(fmt.Sprintf(`{"profile":"dev","production":%t,"sources":["zz-prod-nginx"],"session_ends_in_s":987654,"auto_approve":true,"epoch_id":9007199254740993}`, f.production))
		if f.status != nil {
			b = f.status
		}
		switch r := result.(type) {
		case *json.RawMessage:
			*r = b
		default:
			_ = json.Unmarshal(b, r)
		}
		return nil
	}
	if f.err != nil {
		return f.err
	}
	if r, ok := result.(*json.RawMessage); ok {
		*r = json.RawMessage(`{"records":[{"msg":"render pdf for ⟦email:7F3KQ2M9ZD4X⟧ failed","order_id":9007199254740993,"retried":false,"user":null}],"complete":true}`)
	}
	return nil
}
func (f *fakeConn) Close() error { return nil }

func (f *fakeConn) methods() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

func connect(t *testing.T, o Options) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	st, ct := mcp.NewInMemoryTransports()
	ss, err := New(o).Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close(); ss.Close() })
	return cs
}

func withConn(c *fakeConn) Options {
	return Options{Profiles: func() ([]string, error) { return []string{"dev"}, nil }, Dial: func(string) (Conn, error) { return c, nil }}
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return res
}

func text(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

func TestToolList(t *testing.T) {
	cs := connect(t, withConn(&fakeConn{}))
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, tl := range res.Tools {
		got = append(got, tl.Name)
		if !strings.HasPrefix(tl.Name, "locklog_") {
			t.Errorf("tool %s lacks the locklog_ prefix", tl.Name)
		}
	}
	slices.Sort(got)
	want := Names()
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("tools = %v, want %v", got, want)
	}
}

// Only locklog_request_change is approved among this PR's tools; the
// free list is what an agent may call without a prompt.
func TestFreeNames(t *testing.T) {
	want := []string{ToolStatus, ToolSources, ToolSearch, ToolCount, ToolPatterns, ToolPIIList, ToolPIIAdd}
	if got := FreeNames(); !slices.Equal(got, want) {
		t.Errorf("FreeNames = %v, want %v", got, want)
	}
	if Free(ToolRequestChange) {
		t.Error("locklog_request_change is approved, not free")
	}
	if Free("locklog_unknown") {
		t.Error("an unknown tool counts as free")
	}
}

func TestSearchForwards(t *testing.T) {
	c := &fakeConn{}
	cs := connect(t, withConn(c))
	res := call(t, cs, ToolSearch, map[string]any{
		"sources": []string{"nginx"}, "from": "2026-10-30T13:00:00Z", "text": "upstream timed out",
		"where": []map[string]any{{"field": "status", "op": ">=", "value": 500}}, "limit": 100,
	})
	if res.IsError {
		t.Fatalf("search: %s", text(res))
	}
	out := text(res)
	if !strings.Contains(out, "untrusted") || !strings.Contains(out, "⟦email:7F3KQ2M9ZD4X⟧") {
		t.Errorf("search text: %s", out)
	}
	calls := c.methods()
	if len(calls) != 1 || !strings.HasPrefix(calls[0], logconsole.MethodSearch+" ") {
		t.Fatalf("calls = %q", calls)
	}
	var p map[string]any
	_ = json.Unmarshal([]byte(strings.TrimPrefix(calls[0], logconsole.MethodSearch+" ")), &p)
	if p["text"] != "upstream timed out" || p["limit"] != float64(100) || p["profile"] != nil {
		t.Errorf("params = %v", p)
	}
	call(t, cs, ToolCount, map[string]any{"bucket": "1m", "by": []string{"level"}, "first_last": true})
	if calls := c.methods(); !strings.Contains(calls[1], `"bucket":"1m"`) || !strings.HasPrefix(calls[1], logconsole.MethodCount) {
		t.Errorf("count call = %q", calls[1])
	}
	call(t, cs, ToolSources, nil)
	if calls := c.methods(); !strings.HasPrefix(calls[2], logconsole.MethodSources) {
		t.Errorf("sources call = %q", calls[2])
	}
	call(t, cs, ToolCount, map[string]any{"by_pattern": true})
	if calls := c.methods(); !strings.Contains(calls[3], `"by_pattern":true`) || !strings.HasPrefix(calls[3], logconsole.MethodCount) {
		t.Errorf("count by pattern call = %q", calls[3])
	}
}

// locklog_patterns forwards its range, top and baseline to log.patterns,
// without the profile.
func TestPatternsForwards(t *testing.T) {
	c := &fakeConn{}
	cs := connect(t, withConn(c))
	res := call(t, cs, ToolPatterns, map[string]any{"profile": "dev", "sources": []string{"nginx"}, "last": "1h", "top": 10, "baseline": "24h"})
	if res.IsError {
		t.Fatalf("patterns: %s", text(res))
	}
	if !strings.Contains(text(res), "untrusted") {
		t.Errorf("patterns text: %s", text(res))
	}
	calls := c.methods()
	if len(calls) != 1 || !strings.HasPrefix(calls[0], logconsole.MethodPatterns+" ") {
		t.Fatalf("calls = %q", calls)
	}
	var p map[string]any
	_ = json.Unmarshal([]byte(strings.TrimPrefix(calls[0], logconsole.MethodPatterns+" ")), &p)
	if p["top"] != float64(10) || p["baseline"] != "24h" || p["last"] != "1h" || p["profile"] != nil {
		t.Errorf("params = %v", p)
	}
	// The schema bounds top (the console checks it again).
	if res := call(t, cs, ToolPatterns, map[string]any{"top": 1000}); !res.IsError {
		t.Errorf("top 1000 accepted: %s", text(res))
	}
	if len(c.methods()) != 1 {
		t.Errorf("an out-of-schema call reached the console: %q", c.methods())
	}
}

// locklog_pii_add only tightens the masking: free, and served on a
// production profile to an agent that is not a host agent (lea, its own
// container). The console audits it and shows it in its status (#64).
func TestPIIAddServedOnProductionForNonHostAgents(t *testing.T) {
	c := &fakeConn{production: true}
	cs := connect(t, withConn(c))
	if !Free(ToolPIIAdd) {
		t.Fatal("locklog_pii_add is not free")
	}
	call(t, cs, ToolPIIAdd, map[string]any{"pattern": "customer_name"})
	calls := c.methods()
	if len(calls) != 1 || !strings.HasPrefix(calls[0], ipc.MethodPIIAdd+" ") || !strings.Contains(calls[0], "customer_name") {
		t.Errorf("calls = %q", calls)
	}
}

func TestRefusalIsStructured(t *testing.T) {
	c := &fakeConn{err: &ipc.RPCError{Code: ipc.CodeRefused, Message: "over the budget", Data: &refusal.Info{Code: "E_OVER_BUDGET", Hint: "narrow the range"}}}
	cs := connect(t, withConn(c))
	res := call(t, cs, ToolSearch, map[string]any{"text": "x"})
	if !res.IsError || !strings.Contains(text(res), "over the budget") || !strings.Contains(text(res), "narrow the range") {
		t.Errorf("refusal: %s", text(res))
	}
}

func TestHostAgentGuard(t *testing.T) {
	c := &fakeConn{production: true}
	o := withConn(c)
	o.HostAgent = true
	cs := connect(t, o)
	args := map[string]map[string]any{ToolPIIAdd: {"pattern": "x"}, ToolRequestChange: {"change": "y"}}
	for _, tool := range []string{ToolSearch, ToolCount, ToolPatterns, ToolSources, ToolPIIList, ToolPIIAdd, ToolRequestChange} {
		res := call(t, cs, tool, args[tool])
		if !res.IsError || !strings.Contains(text(res), "non-production trial") {
			t.Errorf("%s on production from a host agent: %s", tool, text(res))
		}
	}
	for _, m := range c.methods() {
		if !strings.HasPrefix(m, ipc.MethodStatus) {
			t.Errorf("a host agent reached %q on production", m)
		}
	}
	if res := call(t, cs, ToolStatus, nil); !strings.Contains(text(res), string(CodeProductionHostAgent)) {
		t.Errorf("status: %s", text(res))
	}
	// Non-production: served.
	c.production = false
	if res := call(t, cs, ToolSearch, map[string]any{"text": "x"}); res.IsError {
		t.Errorf("non-production: %s", text(res))
	}
	// Without the host-agent flag (lea, own container): production served.
	c2 := &fakeConn{production: true}
	cs2 := connect(t, withConn(c2))
	if res := call(t, cs2, ToolSearch, map[string]any{"text": "x"}); res.IsError {
		t.Errorf("own container on production: %s", text(res))
	}
}

// envelope are the keys of StatusOut that frame a profile's answer; the
// text shows their values in prose, not as JSON pairs.
var envelope = map[string]bool{"data": true, "profile": true, "start": true, "running": true, "status": true, "refused": true, "refusal": true}

// scalar renders a decoded JSON leaf as JSON.
func scalar(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// inText reports whether the text shows the pair key: v, compact or
// indented; an integer the structured output holds as a decimal string
// may show as a number.
func inText(txt, key string, v any) bool {
	vals := []string{scalar(v)}
	if s, ok := v.(string); ok && s != "" && strings.Trim(s, "0123456789-") == "" {
		vals = append(vals, s)
	}
	for _, val := range vals {
		if strings.Contains(txt, `"`+key+`":`+val) || strings.Contains(txt, `"`+key+`": `+val) {
			return true
		}
	}
	return false
}

// checkPairs fails for every key/value pair (and array item) under v that
// the text does not show. Envelope keys are containers or prose values.
func checkPairs(t *testing.T, what, txt, key string, v any) {
	t.Helper()
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			checkPairs(t, what, txt, k, e)
		}
		return
	case []any:
		for _, e := range x {
			checkPairs(t, what, txt, key, e)
		}
		return
	}
	switch {
	case key == "running":
		want := "No console runs"
		if v == true {
			want = "console running"
		}
		if !strings.Contains(txt, want) {
			t.Errorf("%s: running=%v but the text lacks %q:\n%s", what, v, want, txt)
		}
	case envelope[key]:
		if s, ok := v.(string); !ok || !strings.Contains(txt, s) {
			t.Errorf("%s: %s=%v is not in the text:\n%s", what, key, v, txt)
		}
	case key == "":
		if !strings.Contains(txt, scalar(v)) {
			t.Errorf("%s: item %v is not in the text:\n%s", what, v, txt)
		}
	default:
		// An array item under key shows as itself.
		if !inText(txt, key, v) && !strings.Contains(txt, scalar(v)) {
			t.Errorf("%s: structured %q: %s is not in the text:\n%s", what, key, scalar(v), txt)
		}
	}
}

// checkParity fails when the structured output holds a key/value pair the
// text does not show: booleans and null included.
func checkParity(t *testing.T, what string, res *mcp.CallToolResult) {
	t.Helper()
	if res.StructuredContent == nil {
		return
	}
	checkPairs(t, what, text(res), "", res.StructuredContent)
}

// statusData is the structured status output, profile by profile.
func statusData(t *testing.T, res *mcp.CallToolResult) []map[string]any {
	t.Helper()
	b, _ := json.Marshal(res.StructuredContent)
	var got struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("structured = %s (%v)", b, err)
	}
	return got.Data
}

// A host agent asking the status of a production profile, or of one whose
// status does not say, gets a structured refusal and no status, in the
// text or the structured output.
func TestHostAgentStatusStructured(t *testing.T) {
	for _, c := range []*fakeConn{{production: true}, {status: []byte(`{"profile":"dev","sources":["zz-prod-nginx"]}`)}, {status: []byte(`[1,`)}} {
		o := withConn(c)
		o.HostAgent = true
		res := call(t, connect(t, o), ToolStatus, nil)
		d := statusData(t, res)
		if len(d) != 1 {
			t.Fatalf("data = %v", d)
		}
		if _, ok := d[0]["status"]; ok {
			t.Errorf("a host agent got the status: %v", d[0])
		}
		r, _ := d[0]["refused"].(map[string]any)
		if r["code"] != string(CodeProductionHostAgent) || r["retry"] != "ask_user" {
			t.Errorf("refused = %v", d[0]["refused"])
		}
		for _, leak := range []string{"zz-prod-nginx", "987654", "auto_approve"} {
			if strings.Contains(text(res), leak) {
				t.Errorf("the text shows the status (%s): %s", leak, text(res))
			}
		}
		checkParity(t, "status", res)
	}
}

// The guard fails closed: a status that does not decode or does not say
// production refuses every tool, structured, before any log method.
func TestHostAgentGuardFailsClosed(t *testing.T) {
	args := map[string]map[string]any{ToolPIIAdd: {"pattern": "x"}, ToolRequestChange: {"change": "y"}}
	for _, st := range []string{`[1,`, `{"profile":"dev"}`, `{"production":"yes"}`} {
		c := &fakeConn{status: []byte(st)}
		o := withConn(c)
		o.HostAgent = true
		cs := connect(t, o)
		for _, tool := range Names()[1:] {
			res := call(t, cs, tool, args[tool])
			b, _ := json.Marshal(res.StructuredContent)
			if !res.IsError || !strings.Contains(string(b), `"code":"E_PRODUCTION_HOST_AGENT"`) || !strings.Contains(string(b), `"retry":"ask_user"`) {
				t.Errorf("%s with status %s: %s %s", tool, st, text(res), b)
			}
		}
		for _, m := range c.methods() {
			if !strings.HasPrefix(m, ipc.MethodStatus) {
				t.Errorf("status %s: a host agent reached %q", st, m)
			}
		}
	}
}

// Large integers keep their digits: as a decimal string when beyond 2^53.
func TestLargeIntegersExact(t *testing.T) {
	cs := connect(t, withConn(&fakeConn{}))
	res := call(t, cs, ToolSearch, map[string]any{"text": "x"})
	b, _ := json.Marshal(res.StructuredContent)
	if !strings.Contains(string(b), `"order_id":"9007199254740993"`) || !strings.Contains(text(res), "9007199254740993") {
		t.Errorf("structured %s, text %s", b, text(res))
	}
	res = call(t, cs, ToolStatus, nil)
	if b, _ := json.Marshal(res.StructuredContent); !strings.Contains(string(b), `"epoch_id":"9007199254740993"`) {
		t.Errorf("status structured %s", b)
	}
}

// The structured output of every tool never carries more than its text:
// served, refused by the console, on production with and without a host
// agent, and without a console.
func TestStructuredParity(t *testing.T) {
	args := map[string]map[string]any{ToolSearch: {"text": "x"}, ToolCount: {"text": "x"}, ToolPIIAdd: {"pattern": "x"}, ToolRequestChange: {"change": "y"}}
	refused := &ipc.RPCError{Code: ipc.CodeRefused, Message: "over the budget", Data: &refusal.Info{Code: "E_OVER_BUDGET", Retry: refusal.RetryRewrite, Hint: "narrow the range", Span: &refusal.Span{Line: 1, Col: 7, Token: "regex"}}}
	cases := []struct {
		name string
		conn *fakeConn
		host bool
	}{
		{"served", &fakeConn{}, false},
		{"served production", &fakeConn{production: true}, false},
		{"console refusal", &fakeConn{err: refused}, false},
		{"host agent production", &fakeConn{production: true}, true},
		{"host agent non-production", &fakeConn{}, true},
		{"host agent status without production", &fakeConn{status: []byte(`{"profile":"dev","sources":["zz-prod-nginx"]}`)}, true},
	}
	for _, tc := range cases {
		o := withConn(tc.conn)
		o.HostAgent = tc.host
		cs := connect(t, o)
		for _, tool := range Names() {
			checkParity(t, tc.name+"/"+tool, call(t, cs, tool, args[tool]))
		}
	}
	o := withConn(nil)
	o.Dial = func(string) (Conn, error) { return nil, client.ErrNoConsole }
	cs := connect(t, o)
	for _, tool := range Names() {
		checkParity(t, "no console/"+tool, call(t, cs, tool, args[tool]))
	}
}

// The input schemas bound what an agent may send.
func TestInputSchemas(t *testing.T) {
	cs := connect(t, withConn(&fakeConn{}))
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	schemas := map[string]map[string]any{}
	raw := map[string]string{}
	for _, tl := range res.Tools {
		b, _ := json.Marshal(tl.InputSchema)
		raw[tl.Name] = string(b)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		schemas[tl.Name] = m
	}
	prop := func(tool string, path ...string) map[string]any {
		m := schemas[tool]
		for _, p := range path {
			m, _ = m[p].(map[string]any)
		}
		return m
	}
	ops := []any{"=", "!=", "in", "exists", "<", "<=", ">", ">=", "contains", "matches"}
	if l := prop(ToolSearch, "properties", "limit"); l["minimum"] != float64(1) || l["maximum"] != float64(200) {
		t.Errorf("search limit = %v", l)
	}
	if tp := prop(ToolPatterns, "properties", "top"); tp["minimum"] != float64(1) || tp["maximum"] != float64(100) {
		t.Errorf("patterns top = %v", tp)
	}
	if b := prop(ToolPatterns, "properties", "baseline"); b["maxLength"] == nil {
		t.Errorf("patterns baseline = %v", b)
	}
	for _, tool := range []string{ToolSearch, ToolCount, ToolPatterns} {
		pred := prop(tool, "properties", "where", "items", "properties")
		op, _ := pred["op"].(map[string]any)
		val, _ := pred["value"].(map[string]any)
		if e, _ := op["enum"].([]any); !slices.Equal(e, ops) || val["maxLength"] != float64(1024) {
			t.Errorf("%s predicate = %v", tool, pred)
		}
		if r := prop(tool, "properties", "regex"); r["maxLength"] != float64(256) {
			t.Errorf("%s regex = %v", tool, r)
		}
	}
	for tool, f := range map[string]string{ToolPIIAdd: "pattern", ToolRequestChange: "change"} {
		if p := prop(tool, "properties", f); p["minLength"] != float64(1) || p["maxLength"] == nil {
			t.Errorf("%s %s = %v", tool, f, p)
		}
	}
	for _, unused := range []string{"limit", "fields"} {
		if _, ok := prop(ToolCount, "properties")[unused]; ok {
			t.Errorf("count schema has %s", unused)
		}
	}
	if _, ok := prop(ToolCount, "properties")["bucket"]; !ok {
		t.Error("count schema lacks bucket")
	}
	for tool, r := range raw {
		if strings.Contains(r, "locklog_lookup") {
			t.Errorf("the %s schema names locklog_lookup", tool)
		}
	}
	for _, bad := range []map[string]any{
		{"limit": 0}, {"limit": 201},
		{"where": []map[string]any{{"field": "a", "op": "~"}}},
		{"where": []map[string]any{{"field": "a", "op": "=", "value": strings.Repeat("x", 1025)}}},
	} {
		if r, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: ToolSearch, Arguments: bad}); err == nil && !r.IsError {
			t.Errorf("search accepted %v", bad)
		}
	}
	for tool, bad := range map[string]map[string]any{ToolPIIAdd: {"pattern": ""}, ToolRequestChange: {"change": ""}, ToolCount: {"limit": 5}} {
		if r, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: bad}); err == nil && !r.IsError {
			t.Errorf("%s accepted %v", tool, bad)
		}
	}
}
