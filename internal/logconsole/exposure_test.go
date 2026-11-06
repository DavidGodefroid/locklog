//go:build unix

package logconsole

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/ipc"
)

// The exposure count: distinct records per pseudonym, in the epoch in
// force only; a new epoch starts it again; past its bound, lower bounds.
func TestExposureCount(t *testing.T) {
	start := time.Date(2026, 11, 6, 9, 0, 0, 0, time.UTC)
	x := NewExposure(start)
	x.Add("E1", []ExposedRecord{{Key: "r1", Pseudonyms: []string{"⟦email:A⟧", "⟦email:B⟧"}}, {Key: "r2", Pseudonyms: []string{"⟦email:A⟧"}}})
	// The same record returned again counts once.
	x.Add("E1", []ExposedRecord{{Key: "r1", Pseudonyms: []string{"⟦email:A⟧"}}})
	n, exact, since := x.Count("E1", []string{"⟦email:A⟧", "⟦email:B⟧", "⟦email:C⟧"})
	if n[0] != 2 || n[1] != 1 || n[2] != 0 || !exact || !since.Equal(start) {
		t.Fatalf("counts %v %v %v", n, exact, since)
	}
	if n, _, _ := x.Count("E0", []string{"⟦email:A⟧"}); n[0] != 0 {
		t.Fatalf("another epoch: %v", n)
	}
	x.Add("E2", []ExposedRecord{{Key: "r3", Pseudonyms: []string{"⟦email:D⟧"}}})
	if n, _, _ := x.Count("E1", []string{"⟦email:A⟧"}); n[0] != 0 {
		t.Fatalf("the old epoch kept: %v", n)
	}
	if n, exact, since := x.Count("E2", []string{"⟦email:D⟧"}); n[0] != 1 || !exact || !since.Equal(start) {
		t.Fatalf("new epoch: %v %v %v", n, exact, since)
	}
	x.pairs = maxExposurePairs
	x.Add("E2", []ExposedRecord{{Key: "r4", Pseudonyms: []string{"⟦email:D⟧"}}})
	if n, exact, _ := x.Count("E2", []string{"⟦email:D⟧"}); n[0] != 1 || exact {
		t.Fatalf("past the bound: %v %v", n, exact)
	}
	var none *Exposure
	none.Add("E1", []ExposedRecord{{Key: "r1", Pseudonyms: []string{"⟦email:A⟧"}}})
	if _, exact, _ := none.Count("E1", []string{"⟦email:A⟧"}); exact {
		t.Fatal("no count is exact")
	}
}

// exposingEngine names the records of its result.
type exposingEngine struct {
	fakeEngine
	seen *Exposure
}

func (e *exposingEngine) Handle(ctx context.Context, m string, p json.RawMessage, c Caller) (any, *Refusal, error) {
	e.seen = ExposureFrom(ctx)
	return e.fakeEngine.Handle(ctx, m, p, c)
}

func (e *exposingEngine) Exposed(any) (string, []ExposedRecord) {
	return "E1", []ExposedRecord{{Key: "r1", Pseudonyms: []string{"⟦email:A⟧"}}}
}

// The records an answered, audited call returned are counted; a call that
// could not be audited (refused) is not; the engine gets the count.
func TestHandlerCountsExposure(t *testing.T) {
	b := New(Options{Profile: "staging", Root: project(t, localCfg)})
	pol, err := b.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	eng := &exposingEngine{fakeEngine: fakeEngine{result: map[string]any{"records": []string{}}}}
	env := &fakeEnv{sess: &session{engine: eng, policy: pol.(Policy)}, policy: pol, failSave: true}
	ctx := console.WithPeer(context.Background(), ipc.Cred{UID: 1000, PID: 42})
	b.Methods()[MethodSearch](ctx, ipc.Request{ID: 1, Method: MethodSearch, Params: json.RawMessage(`{}`)}, env)
	if n, _, _ := b.exp.Count("E1", []string{"⟦email:A⟧"}); n[0] != 0 {
		t.Fatal("an unaudited answer was counted")
	}
	env.failSave = false
	b.Methods()[MethodSearch](ctx, ipc.Request{ID: 2, Method: MethodSearch, Params: json.RawMessage(`{}`)}, env)
	if n, _, _ := b.exp.Count("E1", []string{"⟦email:A⟧"}); n[0] != 1 {
		t.Fatalf("count %v", n)
	}
	if eng.seen != b.exp {
		t.Error("the engine did not get the console's count")
	}
	eng.refuse = &Refusal{Message: "no"}
	b.Methods()[MethodSearch](ctx, ipc.Request{ID: 3, Method: MethodSearch, Params: json.RawMessage(`{}`)}, env)
}
