//go:build unix

package logconsole

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/ipc"
	"github.com/DavidGodefroid/lockkit/plans"
	"github.com/DavidGodefroid/lockkit/ticket"
)

// The ticket and the requester of an approved method are the console's:
// the engine gets the rest, standalone too.
func TestSplitEnvelope(t *testing.T) {
	out, env, ok := splitEnvelope(json.RawMessage(`{"ref":"Lr1.x","ticket":"T1","requester":{"agent":"dev-1","token":"ab"},"pseudonyms":["⟦email:A⟧"]}`))
	if !ok || env.Ticket != "T1" || env.Requester != (ipc.Requester{Agent: "dev-1", Token: "ab"}) {
		t.Fatalf("envelope %+v %v", env, ok)
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(out, &m) != nil || len(m) != 2 || m["ref"] == nil || m["pseudonyms"] == nil {
		t.Fatalf("params %s", out)
	}
	for _, bad := range []string{`{"ticket":1}`, `{"requester":"x"}`} {
		if _, _, ok := splitEnvelope(json.RawMessage(bad)); ok {
			t.Errorf("%s accepted", bad)
		}
	}
	// Not an object: left to the engine, which refuses it.
	if out, _, ok := splitEnvelope(json.RawMessage(`[1]`)); !ok || string(out) != `[1]` {
		t.Errorf("array: %s %v", out, ok)
	}

	b := New(Options{Profile: "staging", Root: project(t, localCfg)})
	pol, err := b.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	eng := &fakeEngine{result: map[string]any{"values": []string{}}}
	fe := &fakeEnv{sess: &session{engine: eng, policy: pol.(Policy)}, policy: pol}
	ctx := console.WithPeer(context.Background(), ipc.Cred{UID: 1000, PID: 42})
	resp := b.Methods()[MethodUnmask](ctx, ipc.Request{ID: 3, Method: MethodUnmask,
		Params: json.RawMessage(`{"ref":"Lr1.x","pseudonyms":["⟦email:A⟧"],"reason":"r","requester":{"agent":"dev-1","token":"ab"}}`)}, fe)
	if resp.Error != nil || strings.Contains(eng.params, "requester") || !strings.Contains(eng.params, `"ref":"Lr1.x"`) {
		t.Fatalf("standalone: %+v, engine got %s", resp.Error, eng.params)
	}
	// A free method is not touched: an unknown field is the engine's.
	b.Methods()[MethodSearch](ctx, ipc.Request{ID: 4, Method: MethodSearch, Params: json.RawMessage(`{"ticket":"T1"}`)}, fe)
	if eng.params != `{"ticket":"T1"}` {
		t.Errorf("search params %s", eng.params)
	}
}

// A keyed digest goes to the ticket in its hash form, still keyed.
func TestHubHash(t *testing.T) {
	h, err := hubHash("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
	if err != nil || h != "sha256:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" {
		t.Fatalf("%s %v", h, err)
	}
	for _, bad := range []string{"", "not base64!", "AAEC"} {
		if _, err := hubHash(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// A renewal is checked against the policy in force; what needs the record
// is named unchecked, the plan hash stays the stored one.
func TestRecompute(t *testing.T) {
	b := New(Options{Profile: "staging"})
	body, _ := json.Marshal(hubBody{Method: MethodUnmask, Moving: []string{"epoch", "record"}})
	p := &plans.Plan{Body: body, Binding: plans.Binding{PlanHash: "sha256:aa", PolicyFP: "sha256:bb",
		Inputs: map[string]string{"ref": "sha256:1", "record": "sha256:2", "epoch": "sha256:3", "spans": "sha256:4"}}}
	if _, _, _, err := b.recompute(p); err == nil {
		t.Error("recomputed with no policy in force")
	}
	b.fp = "sha256:cc"
	fp, hash, in, err := b.recompute(p)
	if err != nil || fp != "sha256:cc" || hash != "sha256:aa" {
		t.Fatalf("%s %s %v", fp, hash, err)
	}
	want := map[string]string{"ref": "sha256:1", "record": ticket.UncheckedInput, "epoch": ticket.UncheckedInput, "spans": "sha256:4"}
	for k, v := range want {
		if in[k] != v {
			t.Errorf("input %s = %q, want %q", k, in[k], v)
		}
	}
	if p.Binding.Inputs["record"] != "sha256:2" {
		t.Error("the stored inputs were changed")
	}
}

// locklog_status in hub mode: the engine's status and the instance, never
// the hub's key or URL.
func TestStatusWithHub(t *testing.T) {
	st := withHub(map[string]any{"epoch": "E1"}, &console.Hub{Instance: "logs"})
	raw, _ := json.Marshal(st)
	if string(raw) != `{"epoch":"E1","hub":{"mode":"hub","instance":"logs"}}` {
		t.Errorf("status %s", raw)
	}
}

func TestPeerName(t *testing.T) {
	if peerName(10052) != "agent (uid 10052)" || peerName(1000) != "uid 1000" {
		t.Errorf("%q %q", peerName(10052), peerName(1000))
	}
}
