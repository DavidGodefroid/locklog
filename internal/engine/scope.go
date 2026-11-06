package engine

import (
	"context"
	"time"
)

// Approval is what the engine asks the human to approve (an approval
// screen of the console): a scan (class read), an unmask or an approved
// lookup (class read-pii).
type Approval struct {
	// Class is "read" or "read-pii".
	Class  string
	Header string
	// Note is the agent's reason (untrusted: the console escapes it).
	Note     string
	Body     []string
	Warnings []string
	// NeverAuto: auto mode never approves it.
	NeverAuto bool
	// Clear is the clear view of the screen's record (secrets and
	// redactions kept), for the console's own terminal only: the
	// console shows it when its clear-results switch (Ctrl-O) is on.
	// It never reaches the agent, nor a hub.
	Clear []string
}

// Approver asks the human. It returns nil once approved; any other error
// is the console's answer (a denial, a timeout, a pending ticket), passed
// back unchanged as the engine's error.
type Approver func(ctx context.Context, a Approval) error

// Peer is the caller of a call: its kernel-verified uid and the console's
// approver.
type Peer struct {
	UID int
	// Known: the uid was verified by the kernel (peer credentials).
	Known   bool
	Approve Approver
}

type peerKey struct{}

// WithPeer attaches the caller of a call to ctx.
func WithPeer(ctx context.Context, p Peer) context.Context {
	return context.WithValue(ctx, peerKey{}, &p)
}

// peerFrom returns the caller of a call (the zero peer, with no approver,
// when none was attached).
func peerFrom(ctx context.Context) Peer {
	if p, ok := ctx.Value(peerKey{}).(*Peer); ok {
		return *p
	}
	return Peer{}
}

// scanKey carries the approved scan a call runs under (Scan).
type scanKey struct{}

func withScan(ctx context.Context, s *scanCall) context.Context {
	return context.WithValue(ctx, scanKey{}, s)
}

func scanFrom(ctx context.Context) *scanCall {
	s, _ := ctx.Value(scanKey{}).(*scanCall)
	return s
}

// limits are the per-call budgets of a call: the engine's, or for a call
// of an approved scan the scan's own (its whole plan, its own deadline).
func (e *Engine) limits(ctx context.Context) Limits {
	l := e.o.Limits
	if sc := scanFrom(ctx); sc != nil {
		r := e.o.ScanRange
		l.LocalRange, l.RemoteRange, l.CountRange, l.RemoteCountRange = r, r, r, r
		l.LocalBytes, l.RemoteBytes = e.o.ScanBytes, e.o.ScanBytes
		l.Deadline = sc.deadline()
	}
	return l
}

// callBytes is the bytes one call may process (remote sources, whose
// plans have no byte size before the fetch, stop there with a cursor).
// A call naming no source reads them all. A call of an approved scan
// processes as much (its plan may be far larger: it continues free).
func (e *Engine) callBytes(_ context.Context, srcs []string) int64 {
	if len(srcs) == 0 {
		srcs = e.names
	}
	n := e.o.Limits.LocalBytes
	for _, s := range srcs {
		if _, ok := e.o.Sources[s]; ok && e.remote(s) {
			n = min(n, e.o.Limits.RemoteBytes)
		}
	}
	return n
}

// scanCallBudget is the most one call of an approved scan may take from
// its request, the approval wait included: under the 600 s client
// timeouts.
const scanCallBudget = 570 * time.Second
