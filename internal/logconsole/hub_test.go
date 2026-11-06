//go:build unix

package logconsole

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/hubclient/hubtest"
	"github.com/DavidGodefroid/lockkit/ipc"
	"github.com/DavidGodefroid/lockkit/plans"
	"github.com/DavidGodefroid/lockkit/ticket"
)

// The ticket and the requester of an approved method are the console's:
// the engine gets the rest, also before the hub is open.
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
		t.Fatalf("no hub: %+v, engine got %s", resp.Error, eng.params)
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

// A local-only console may be on one network, the hub's, once its hub is
// open; before, it has none, and never two.
func TestChecksNetworkHubMode(t *testing.T) {
	eng := &fakeEngine{}
	open := func(context.Context, OpenOptions) (Engine, error) { return eng, nil }
	for _, tt := range []struct {
		name   string
		ifs    []string
		hub    bool
		refuse bool
	}{
		{"no hub yet, one interface", []string{"eth0"}, false, true},
		{"hub, the hub's network", []string{"eth0"}, true, false},
		{"hub, two networks", []string{"eth0", "eth1"}, true, true},
		{"hub, no network", nil, true, false},
	} {
		net := t.TempDir()
		for _, n := range append([]string{"lo"}, tt.ifs...) {
			if err := os.Mkdir(filepath.Join(net, n), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		b := New(Options{Profile: "staging", Root: project(t, localCfg), SysClassNet: net, Open: open})
		pol, err := b.LoadPolicy()
		if err != nil {
			t.Fatal(err)
		}
		b.o.InContainer = true
		if tt.hub {
			b.hub = &console.Hub{Instance: "logs"}
		}
		f := b.Checks(context.Background(), &session{engine: eng, policy: pol.(Policy)})
		if (len(f) > 0 && f[0].Refuse) != tt.refuse {
			t.Errorf("%s: findings %+v", tt.name, f)
		}
	}
}

// hubEnv is a console in hub mode.
type hubEnv struct {
	*fakeEnv
	h *console.Hub
}

func (e *hubEnv) Hub() *console.Hub { return e.h }

// hubRig is a backend in hub mode against lockkit's fake hub.
type hubRig struct {
	hub *hubtest.Hub
	h   *console.Hub
	b   *Backend
	env *hubEnv
}

func newHubRig(t *testing.T, eng Engine) *hubRig {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	hb := hubtest.New(t, "logs", pub)
	st, err := plans.Open(filepath.Join(t.TempDir(), "plans"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := hubclient.New(hubclient.Config{URL: hb.URL(), Instance: "logs", Key: priv, HubKey: hb.Pub, StateFile: filepath.Join(t.TempDir(), "hub-state.json")})
	if err != nil {
		t.Fatal(err)
	}
	b := New(Options{Profile: "staging", Root: project(t, localCfg)})
	pol, err := b.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	h := &console.Hub{Client: c, Store: st, Instance: "logs"}
	b.OnHub(h)
	env := &hubEnv{fakeEnv: &fakeEnv{sess: &session{engine: eng, policy: pol.(Policy)}, policy: pol}, h: h}
	return &hubRig{hub: hb, h: h, b: b, env: env}
}

// call calls method as peer uid 1000 with agent token tok (and ticket tk).
func (r *hubRig) call(t *testing.T, method, tok, tk string) ipc.Response {
	t.Helper()
	p := map[string]any{"kind": "email", "values": []string{"x"}, "requester": map[string]string{"agent": "dev-1", "token": tok}}
	if tk != "" {
		p["ticket"] = tk
	}
	raw, _ := json.Marshal(p)
	ctx := console.WithPeer(context.Background(), ipc.Cred{UID: 1000, PID: 42})
	return r.b.Methods()[method](ctx, ipc.Request{ID: 7, Method: method, Params: raw}, r.env)
}

func pendingTicket(t *testing.T, resp ipc.Response) string {
	t.Helper()
	var p struct{ Status, Ticket string }
	if resp.Error != nil || json.Unmarshal(resp.Result, &p) != nil || p.Status != "pending" || p.Ticket == "" {
		t.Fatalf("not pending: %+v %s", resp.Error, resp.Result)
	}
	return p.Ticket
}

// hubAsking asks the hub to approve a fixed plan, then answers (or
// panics, once approved).
type hubAsking struct {
	fakeEngine
	panics bool
}

var fixedPlan = base64.RawURLEncoding.EncodeToString(make([]byte, 32))

func (e *hubAsking) Handle(ctx context.Context, m string, p json.RawMessage, c Caller) (any, *Refusal, error) {
	hc := HubCallFrom(ctx)
	if hc == nil {
		return nil, nil, errors.New("no hub call")
	}
	if err := hc.Approve(ctx, HubRequest{Risk: ticket.RiskReadPII, Header: "lookup · read-pii", PlanHash: fixedPlan}); err != nil {
		return nil, nil, err
	}
	if e.panics {
		panic("engine bug")
	}
	return map[string]any{"pseudonyms": []string{}}, nil, nil
}

// A call whose audit fails withdraws the ticket it submitted, never the
// pending ticket of an earlier call it was lent (the same request).
func TestHubWithdrawOnlyOwnPlan(t *testing.T) {
	r := newHubRig(t, &hubAsking{})
	tk := pendingTicket(t, r.call(t, MethodLookup, "tok-1", ""))
	r.env.failSave = true
	if resp := r.call(t, MethodLookup, "tok-1", ""); resp.Error == nil || !strings.Contains(resp.Error.Message, "audited") {
		t.Fatalf("unaudited call answered: %+v", resp)
	}
	if _, ok := r.hub.Withdrawn(tk); ok {
		t.Fatal("the earlier call's ticket was withdrawn")
	}
	p, err := r.h.Store.TicketPlan(tk)
	if err != nil || p.State != plans.Pending {
		t.Fatalf("lent plan: %+v %v", p, err)
	}
	// A request of its own, unaudited: withdrawn.
	other := newHubRig(t, &hubAsking{})
	other.env.failSave = true
	other.call(t, MethodLookup, "tok-1", "")
	ids := other.hub.Tickets()
	if len(ids) != 1 {
		t.Fatalf("tickets %v", ids)
	}
	if _, ok := other.hub.Withdrawn(ids[0]); !ok {
		t.Fatal("an unaudited call's own ticket was not withdrawn")
	}
}

// A panic of the engine during a ticket's run still finishes its plan: the
// hub hears it consumed, the plan is not left executing.
func TestHubFinishOnPanic(t *testing.T) {
	eng := &hubAsking{}
	r := newHubRig(t, eng)
	tk := pendingTicket(t, r.call(t, MethodLookup, "tok-1", ""))
	r.hub.Decide(tk, ticket.Approved, "")
	if _, err := r.h.Client.Poll(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	eng.panics = true
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("no panic")
			}
		}()
		r.call(t, MethodLookup, "tok-1", tk)
	}()
	p, err := r.h.Store.TicketPlan(tk)
	if err != nil || !p.State.Final() {
		t.Fatalf("plan after a panic: %+v %v", p, err)
	}
	if !r.hub.Consumed(tk) {
		t.Error("the hub was not told the ticket was consumed")
	}
}

// Without peer credentials, an approved method's call that needs no
// approval runs (a free lookup); one that needs an approval is refused,
// never pushed to the hub.
func TestHubNoPeerCredentials(t *testing.T) {
	free := &fakeEngine{result: map[string]any{"pseudonyms": []string{"⟦email:A⟧"}}}
	r := newHubRig(t, free)
	raw := json.RawMessage(`{"kind":"email","values":["x"]}`)
	if resp := r.b.Methods()[MethodLookup](context.Background(), ipc.Request{ID: 1, Method: MethodLookup, Params: raw}, r.env); resp.Error != nil {
		t.Fatalf("free lookup without peer credentials: %+v", resp.Error)
	}
	asking := newHubRig(t, &hubAsking{})
	resp := asking.b.Methods()[MethodLookup](context.Background(), ipc.Request{ID: 2, Method: MethodLookup, Params: raw}, asking.env)
	if resp.Error == nil || !strings.Contains(resp.Error.Message, "peer credentials") || resp.Error.Data == nil || resp.Error.Data.Code != "E_APPROVAL" {
		t.Fatalf("approval without peer credentials: %+v", resp.Error)
	}
	if asking.hub.Pushed() != 0 {
		t.Fatal("a ticket was pushed without peer credentials")
	}
	if rec := asking.env.records[len(asking.env.records)-1].(Record); rec.Decision != "refused" || rec.Code != "E_APPROVAL" {
		t.Errorf("record %+v", rec)
	}
}
