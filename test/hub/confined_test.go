//go:build unix

package hub

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/confine"
	"github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/ipc"
)

// TestConfinedAgent (#158, lockkit#133): over the console's socket, an
// agent that does not run confined is refused with CodeUnconfined, as is
// one whose hello carries no report (an older client); a confined one is
// served. No method is served before an accepted hello.
func TestConfinedAgent(t *testing.T) {
	r := newRig(t, rigOpts{})
	path := r.serveSocket()

	early := dialRaw(t, path)
	if err := early.Call(context.Background(), ipc.MethodStatus, nil, nil); err == nil ||
		!strings.Contains(err.Error(), "hello first") {
		t.Errorf("status before hello: %v, want refused (hello first)", err)
	}

	for name, conf := range map[string]*ipc.Confinement{
		"unconfined": {Reasons: []string{confine.InContainer}},
		"old client": nil,
	} {
		err := dialRaw(t, path).hello(conf)
		var re *ipc.RPCError
		if !errors.As(err, &re) || re.Code != ipc.CodeUnconfined {
			t.Errorf("%s: hello = %v, want CodeUnconfined", name, err)
		}
	}

	s := dialSock(t, path)
	if err := s.Call(context.Background(), ipc.MethodStatus, nil, nil); err != nil {
		t.Errorf("confined agent: status = %v", err)
	}
}

// TestUnconfinedProfile: with unconfined = true on a non-production
// profile, an unconfined agent is served and the console says so.
func TestUnconfinedProfile(t *testing.T) {
	r := newRig(t, rigOpts{extra: "unconfined = true"})
	s := dialRaw(t, r.serveSocket())
	if err := s.hello(&ipc.Confinement{Reasons: []string{confine.InContainer}}); err != nil {
		t.Fatalf("hello: %v", err)
	}
	if err := s.Call(context.Background(), ipc.MethodStatus, nil, nil); err != nil {
		t.Errorf("status: %v", err)
	}
	if !strings.Contains(r.io.output(), console.UnconfinedBanner) {
		t.Errorf("no unconfined banner: %q", r.io.output())
	}
}
