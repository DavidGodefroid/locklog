package mcptools

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/DavidGodefroid/lockkit/ipc"
	"github.com/DavidGodefroid/lockkit/refusal"

	"github.com/DavidGodefroid/locklog/internal/logconsole"
)

type fakeConn struct {
	mu         sync.Mutex
	calls      []string
	production bool
	err        error
}

func (f *fakeConn) Call(_ context.Context, method string, params, result any) error {
	raw, _ := json.Marshal(params)
	f.mu.Lock()
	f.calls = append(f.calls, method+" "+string(raw))
	f.mu.Unlock()
	if method == ipc.MethodStatus {
		b, _ := json.Marshal(map[string]any{"profile": "dev", "production": f.production})
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
		*r = json.RawMessage(`{"records":[{"msg":"render pdf for ⟦email:7F3KQ2M9ZD4X⟧ failed"}],"complete":true}`)
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
	want := []string{ToolStatus, ToolSources, ToolSearch, ToolCount, ToolPIIList, ToolPIIAdd}
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
	for _, tool := range []string{ToolSearch, ToolCount, ToolSources, ToolPIIList, ToolPIIAdd, ToolRequestChange} {
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
	if res := call(t, cs, ToolStatus, nil); !strings.Contains(text(res), "refused to a host agent") {
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
