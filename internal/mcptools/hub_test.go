package mcptools

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/ipc"
	"github.com/DavidGodefroid/lockkit/mcpkit"
)

// The approved tools send the ticket and the requester (lea's agent and
// its token hash) to the console; a pending answer is mcpkit's, with the
// ticket, the lock and the instance only.
func TestApprovedToolsHubMode(t *testing.T) {
	c := &fakeConn{answer: []byte(`{"status":"pending","ticket":"01JBX3V6ZK5Q2M9R8T7W4Y1C0D","lock":"locklog","instance":"logs"}`)}
	o := withConn(c)
	o.Requester = ipc.Requester{Agent: "dev-1", Token: "3f2a"}
	cs := connect(t, o)
	for _, tc := range []struct {
		tool string
		args map[string]any
	}{
		{ToolUnmask, map[string]any{"ref": "Lr1x", "pseudonyms": []string{"⟦email:7F3KQ2M9ZD4X⟧"}, "reason": "r", "ticket": "01JBX3V6ZK5Q2M9R8T7W4Y1C0D"}},
		{ToolScan, map[string]any{"tool": "search", "query": map[string]any{"from": "2026-10-30T13:00:00Z"}, "ticket": "01JBX3V6ZK5Q2M9R8T7W4Y1C0D"}},
		{ToolLookup, map[string]any{"kind": "email", "values": []string{"a@example.com"}, "ticket": "01JBX3V6ZK5Q2M9R8T7W4Y1C0D"}},
	} {
		res := call(t, cs, tc.tool, tc.args)
		if res.IsError || text(res) != mcpkit.PendingText("locklog", "01JBX3V6ZK5Q2M9R8T7W4Y1C0D") {
			t.Errorf("%s: %s", tc.tool, text(res))
		}
		sc, _ := json.Marshal(res.StructuredContent)
		var out struct {
			Data map[string]string `json:"data"`
		}
		if json.Unmarshal(sc, &out) != nil || len(out.Data) != 4 || out.Data["status"] != "pending" || out.Data["instance"] != "logs" {
			t.Errorf("%s: structured %s", tc.tool, sc)
		}
		calls := c.methods()
		last := calls[len(calls)-1]
		if !strings.Contains(last, `"ticket":"01JBX3V6ZK5Q2M9R8T7W4Y1C0D"`) || !strings.Contains(last, `"requester":{"agent":"dev-1","token":"3f2a"}`) {
			t.Errorf("%s: sent %s", tc.tool, last)
		}
	}
	// Without lea and without a ticket, neither is sent.
	c2 := &fakeConn{}
	cs2 := connect(t, withConn(c2))
	call(t, cs2, ToolUnmask, map[string]any{"ref": "Lr1x", "pseudonyms": []string{"⟦email:7F3KQ2M9ZD4X⟧"}, "reason": "r"})
	if calls := c2.methods(); strings.Contains(calls[len(calls)-1], "ticket") || strings.Contains(calls[len(calls)-1], "requester") {
		t.Errorf("sent %s", calls[len(calls)-1])
	}
	// The free tools take no ticket.
	res, err := cs2.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range res.Tools {
		raw, _ := json.Marshal(tl.InputSchema)
		has := strings.Contains(string(raw), `"ticket"`)
		if want := tl.Name == ToolScan || tl.Name == ToolUnmask || tl.Name == ToolLookup; has != want {
			t.Errorf("%s: ticket in its schema = %v", tl.Name, has)
		}
	}
}
