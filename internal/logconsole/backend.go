// Package logconsole is locklog's console backend for lockkit: the agent's
// log methods (log.status, log.sources, log.search, log.count, ...), the
// checks the console makes before it opens a log (the mount roots and the
// .locklog directory the launcher checked, no network it was not given),
// the policy of a profile, and the audit record of every call. lockkit's
// console holds the terminal, the policy review, the approval screens and
// the audit log; the engine (Engine) reads and masks the logs.
package logconsole

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DavidGodefroid/lockkit/audit"
	kconfig "github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/ipc"
	"github.com/DavidGodefroid/lockkit/refusal"
	"github.com/DavidGodefroid/lockkit/sanitize"

	"github.com/DavidGodefroid/locklog/internal/config"
	"github.com/DavidGodefroid/locklog/internal/egress"
	"github.com/DavidGodefroid/locklog/internal/product"
)

// The agent's methods. Each is free (no approval) within the budgets the
// engine enforces, and audited.
const (
	MethodStatus  = "log.status"
	MethodSources = "log.sources"
	MethodSearch  = "log.search"
	MethodCount   = "log.count"
	// MethodPatterns is the top message templates of a range, optionally
	// against a baseline window (locklog_patterns).
	MethodPatterns = "log.patterns"
	// MethodContext, MethodTrace and MethodTail read around a ref, follow
	// an id across sources and follow new records (locklog_context,
	// locklog_trace, locklog_tail).
	MethodContext = "log.context"
	MethodTrace   = "log.trace"
	MethodTail    = "log.tail"
	// MethodScan is a call over the free budgets, approved once (class
	// read) for its whole plan (locklog_scan); MethodUnmask reveals exact
	// pseudonyms of one record on a read-pii approval (locklog_unmask);
	// MethodLookup gives the pseudonyms of clear values, rate-limited
	// (locklog_lookup). Policy changes go through the console's own
	// change.request (locklog_request_change).
	MethodScan   = "log.scan"
	MethodUnmask = "log.unmask"
	MethodLookup = "log.lookup"
)

// Methods lists the methods served, in a fixed order.
var Methods = []string{MethodStatus, MethodSources, MethodSearch, MethodCount, MethodPatterns, MethodContext, MethodTrace, MethodTail,
	MethodScan, MethodUnmask, MethodLookup}

// Approve asks the human to approve a call's operation on the console's
// approval screen (console.Env.Approve for the call's request).
type Approve func(ctx context.Context, s console.Screen) console.Approval

type approveKey struct{}

// WithApprove attaches the call's approver to ctx.
func WithApprove(ctx context.Context, a Approve) context.Context {
	return context.WithValue(ctx, approveKey{}, a)
}

// ApproveFrom returns the call's approver, or nil.
func ApproveFrom(ctx context.Context) Approve {
	a, _ := ctx.Value(approveKey{}).(Approve)
	return a
}

// Declined is an engine's error for a call the human did not approve: Resp
// is the console's answer (a denial, a timeout, a pending ticket), sent to
// the agent as is.
type Declined struct {
	Resp ipc.Response
}

func (d *Declined) Error() string { return "the operation was not approved" }

// Caller is the kernel-verified peer of a call.
type Caller struct{ UID, PID int }

// Refusal is an answer the agent gets as a structured refusal: Message is
// prose that quotes no value of the agent's call nor of the logs; Info
// carries the code (E_OVER_BUDGET, E_PII_IN_QUERY, ...), retry and hint.
type Refusal struct {
	Message string
	Info    refusal.Info
}

// Engine answers the agent's log methods. params is the request's raw
// JSON, validated by the engine; result is a masked, typed value that
// marshals to JSON. A refusal is the agent's error (over budget, a
// personal value in a predicate, ...); err is the engine's own failure.
type Engine interface {
	Handle(ctx context.Context, method string, params json.RawMessage, c Caller) (result any, refused *Refusal, err error)
	// Status is the engine's part of log.status and :status.
	Status(ctx context.Context) any
	Close() error
}

// OpenOptions is what an engine is opened with.
type OpenOptions struct {
	// Policy is the approved policy in force: the engine reads only the
	// sources it names.
	Policy config.Policy
	// Credentials are the secret of the profile's remote source (zero for
	// local sources).
	Credentials egress.Credentials
	// StateDir is the console's state directory (home volume).
	StateDir string
	// Roots are the mount roots of the policy's local sources, checked
	// against the launcher's (PlanRoots): the only directories the
	// sources may be given.
	Roots Roots
	// Project is the project root ("" for none): its .locklog holds the
	// human's PII rules.
	Project string
}

// ErrConnLost is returned (wrapped) by an engine whose logs can no longer
// be trusted to be the ones approved (a mount swapped, the engine closed):
// the console drops the session (console.Env.Lost) and the agent gets
// ipc.CodeConnLost; the next call reconnects, checking everything again.
var ErrConnLost = errors.New("the log session is lost")

// Opener opens the engine of a policy.
type Opener func(ctx context.Context, o OpenOptions) (Engine, error)

// Options locate the profile a console serves and the launcher's checks.
type Options struct {
	Profile string
	// Root is the project root ("" for none).
	Root string
	// StateDir is the console's state base.
	StateDir string
	// Network and ExtraRoots are LOCKLOG_NETWORK and LOCKLOG_EXTRA_ROOTS
	// as the launcher passed them: they are part of the policy.
	Network    string
	ExtraRoots []string
	// ExpectDir and ExpectRoots are LOCKLOG_EXPECT_DIR and
	// LOCKLOG_EXPECT_ROOTS: the device and inode of .locklog and of each
	// mount root, as the launcher checked them on the host.
	ExpectDir   string
	ExpectRoots string
	// DockerRoot is LOCKLOG_DOCKER_ROOT: the containers root the launcher
	// bound for a docker source.
	DockerRoot string
	// InContainer is true in locklog's image (InImage): LOCKLOG_EXPECT_DIR
	// is then required, and Root must be the directory the launcher
	// started the console in.
	InContainer bool
	// SysClassNet is /sys/class/net (tests replace it).
	SysClassNet string
	Open        Opener
}

// Backend implements console.Backend.
type Backend struct {
	o Options
}

var _ console.Backend = (*Backend)(nil)

// New returns the backend of o.Profile.
func New(o Options) *Backend {
	if o.SysClassNet == "" {
		o.SysClassNet = "/sys/class/net"
	}
	return &Backend{o: o}
}

// Sanitizer scrubs locklog's error text: URL userinfo and Authorization
// headers, after the secrets lockkit knows.
func Sanitizer() *sanitize.Sanitizer { return sanitize.New(sanitize.URLUserinfo) }

// Policy is a locklog policy as the console handles it.
type Policy struct {
	config.Policy
}

var _ console.Policy = Policy{}

// Diff implements config.Policy.
func (p Policy) Diff(approved kconfig.Policy) []kconfig.Change {
	if a, ok := approved.(Policy); ok {
		return p.Policy.Diff(a.Policy)
	}
	return p.Policy.Diff(approved)
}

// remote returns the profile's source with credentials, if any.
func (p Policy) remote() (config.Source, bool) {
	for _, s := range p.Policy.Profile.Sources {
		if s.Remote != nil && s.Remote.Credentials != "" {
			return s, true
		}
	}
	return config.Source{}, false
}

// Profile implements console.Policy: the secret the console asks is the
// one of the profile's remote source (one at most), none for local
// sources.
func (p Policy) Profile() console.Profile {
	pr := p.Policy.Profile
	cp := console.Profile{
		Name: pr.Name, Production: pr.Production, Where: where(pr),
		Credentials: console.CredentialsNone, IdleTimeout: pr.IdleTimeout, MaxSession: pr.MaxSession,
	}
	if s, ok := p.remote(); ok {
		cp.Credentials, cp.VaultPath, cp.User = s.Remote.Credentials, s.Remote.VaultPath, s.Remote.User
		if u, err := url.Parse(s.Remote.URL); err == nil {
			cp.Host = u.Hostname()
			cp.DefaultPort = 443
			if u.Scheme == "http" {
				cp.DefaultPort = 80
			}
			cp.Port = cp.DefaultPort
			if n, err := strconv.Atoi(u.Port()); err == nil {
				cp.Port = n
			}
		}
	}
	return cp
}

// where names the sources for the human.
func where(pr config.Profile) string {
	var kinds []string
	for _, s := range pr.Sources {
		k := s.Kind
		if s.Remote != nil {
			k += " " + s.Remote.URL
		}
		if !slices.Contains(kinds, k) {
			kinds = append(kinds, k)
		}
	}
	return strings.Join(kinds, ", ")
}

// LoadPolicy implements console.Backend: the profile from the project's
// .locklog/config.toml with the launch environment.
func (b *Backend) LoadPolicy() (console.Policy, error) {
	// What the launcher checked, before the file is read.
	if err := CheckMounts(b.o); err != nil {
		return nil, err
	}
	if b.o.Root == "" {
		return nil, errors.New("no project: the console serves the profiles of a project's .locklog/config.toml")
	}
	profiles, err := config.LoadFile(kconfig.ProjectConfigPath(product.P, b.o.Root))
	if err != nil {
		return nil, err
	}
	pr, ok := profiles[b.o.Profile]
	if !ok {
		return nil, fmt.Errorf("no profile %q in the config", b.o.Profile)
	}
	n := 0
	for _, s := range pr.Sources {
		if s.Remote != nil && s.Remote.Credentials != "" {
			n++
		}
	}
	if n > 1 {
		return nil, fmt.Errorf("profile %q: at most one remote source with credentials per profile", b.o.Profile)
	}
	p, err := config.NewPolicy(pr, b.o.Network, b.o.ExtraRoots)
	if err != nil {
		return nil, err
	}
	return Policy{p}, nil
}

// session is one open engine.
type session struct {
	engine Engine
	policy Policy

	// done is closed when the session closes: the calls in flight are
	// cancelled (callContext).
	once sync.Once
	done chan struct{}
}

func newSession(e Engine, p Policy) *session {
	return &session{engine: e, policy: p, done: make(chan struct{})}
}

// Close cancels the calls in flight, then closes the engine.
func (s *session) Close() error {
	var err error
	s.once.Do(func() {
		if s.done != nil {
			close(s.done)
		}
		err = s.engine.Close()
	})
	return err
}

// closed reports whether the session was closed.
func (s *session) closed() bool {
	if s.done == nil {
		return false
	}
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

// callContext is ctx, also cancelled when the session closes.
func (s *session) callContext(ctx context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)
	if s.done != nil {
		go func() {
			select {
			case <-s.done:
				cancel()
			case <-ctx.Done():
			}
		}()
	}
	return ctx, cancel
}

// Connect implements console.Backend: the launcher's checks first, then
// the engine of the policy in force.
func (b *Backend) Connect(ctx context.Context, c console.Credentials) (console.Session, error) {
	pol, ok := c.Policy.(Policy)
	if !ok {
		return nil, errors.New("no approved locklog policy to connect to")
	}
	if err := CheckMounts(b.o); err != nil {
		return nil, err
	}
	if b.o.Open == nil {
		return nil, errors.New("this build has no log engine")
	}
	roots, err := PlanRoots(b.o, pol.Policy.Profile)
	if err != nil {
		return nil, err
	}
	var creds egress.Credentials
	if c.Secret != nil {
		creds = egress.Credentials{User: c.User, Secret: string(c.Secret)}
	}
	e, err := b.o.Open(ctx, OpenOptions{Policy: pol.Policy, Credentials: creds, StateDir: b.o.StateDir, Roots: roots, Project: b.o.Root})
	if err != nil {
		return nil, err
	}
	return newSession(e, pol), nil
}

// Checks implements console.Backend: a console with no remote source and
// no LOCKLOG_NETWORK runs with no network; any interface but the loopback
// means it was started otherwise, and it refuses.
func (b *Backend) Checks(ctx context.Context, s console.Session) []console.Finding {
	ls, ok := console.Unwrap(s).(*session)
	if !ok || !b.o.InContainer {
		return nil
	}
	remote := slices.ContainsFunc(ls.policy.Policy.Profile.Sources, func(s config.Source) bool { return s.Remote != nil })
	if remote || b.o.Network != "" {
		return nil
	}
	ifs, err := egress.ExtraInterfaces(b.o.SysClassNet)
	if err != nil {
		return []console.Finding{{Refuse: true, Text: "cannot list the network interfaces: " + Sanitizer().Error(err)}}
	}
	if len(ifs) > 0 {
		return []console.Finding{{Refuse: true, Text: "the console has a network (" + strings.Join(ifs, ", ") + ") but its profile reads only local logs: start it with the launcher (no network)"}}
	}
	return nil
}

// Status implements console.Backend.
func (b *Backend) Status(s console.Session) any {
	ls, ok := console.Unwrap(s).(*session)
	if !ok {
		return nil
	}
	return ls.engine.Status(context.Background())
}

// Methods implements console.Backend.
func (b *Backend) Methods() map[string]console.Handler {
	m := map[string]console.Handler{}
	for _, name := range Methods {
		m[name] = b.handler(name)
	}
	return m
}

func (b *Backend) handler(method string) console.Handler {
	return func(ctx context.Context, req ipc.Request, env console.Env) ipc.Response {
		// Response times levelled: how long a call took says nothing of
		// how much matched.
		start := time.Now()
		defer env.Level(ctx, start)
		var c Caller
		if cred, ok := console.PeerFrom(ctx); ok {
			c = Caller{UID: cred.UID, PID: cred.PID}
		}
		params := req.Params
		if len(params) == 0 {
			params = json.RawMessage("{}")
		}
		// Recorded first: a call refused before the engine runs (no
		// session, a failed reopen) is audited too.
		rec := newRecord(ctx, env, method, params)
		sess, err := env.Session(ctx)
		if err != nil {
			return failed(req.ID, env, rec, ipc.CodeConnLost, env.Sanitizer().Error(err), errNoSessionText)
		}
		ls, ok := console.Unwrap(sess).(*session)
		if !ok {
			return failed(req.ID, env, rec, ipc.CodeInternal, "no log engine", "no log engine")
		}
		// The engine serves the policy it was opened with: once the human
		// approved another one (:review), the session is dropped and
		// reopened on the policy in force before the call runs.
		if p, ok := env.Policy().(Policy); ok && p.Fingerprint() != ls.policy.Fingerprint() {
			env.Lost()
			if sess, err = env.Session(ctx); err != nil {
				return failed(req.ID, env, rec, ipc.CodeConnLost, env.Sanitizer().Error(err), errNoSessionText)
			}
			if ls, ok = console.Unwrap(sess).(*session); !ok || ls.policy.Fingerprint() != p.Fingerprint() {
				return failed(req.ID, env, rec, ipc.CodeInternal, "no log engine for the policy in force", "no log engine for the policy in force")
			}
		}
		// The mounts are checked again on every call (a root swapped
		// after the start): a session whose logs are not the checked ones
		// is dropped, and the next call reconnects, checking them all.
		if err := CheckMounts(b.o); err != nil {
			env.Println("the log mounts changed since the console checked them: the session is closed (" + env.Safe(env.Sanitizer().Error(err)) + ")")
			return lost(req.ID, env, rec)
		}
		cctx, cancel := ls.callContext(ctx)
		cctx = WithApprove(cctx, func(ctx context.Context, s console.Screen) console.Approval { return env.Approve(ctx, req.ID, s) })
		result, refused, err := ls.engine.Handle(cctx, method, params, c)
		cancel()
		var resp ipc.Response
		var declined *Declined
		switch {
		case errors.Is(err, ErrConnLost) || ls.closed():
			// The session ended under the call (Lost, the console
			// closing it): the call ends cleanly, and the session is
			// dropped so that the next call reconnects.
			if err != nil {
				env.Println("log session lost (" + method + "): " + env.Safe(env.Sanitizer().Error(err)))
			}
			return lost(req.ID, env, rec)
		case errors.As(err, &declined):
			// Not approved: the console recorded the decision; the agent
			// gets its answer (a refusal, or a pending ticket).
			rec.Decision = "denied"
			if declined.Resp.Error == nil {
				rec.Decision = "pending"
			}
			resp = declined.Resp
			resp.ID = req.ID
		case ctx.Err() != nil:
			// The agent's connection closed (or the console is
			// stopping): whatever the engine answered, the call is
			// cancelled; nobody reads the answer, but it is audited.
			rec.Decision, rec.Error = "failed", errCancelledText
			resp = console.ErrResp(req.ID, ipc.CodeInternal, errCancelledText)
		case err != nil:
			// The engine's error may quote the call or a log line: the
			// detail is shown on the console only, the agent and the
			// audit get a fixed text.
			env.Println("log engine failure (" + method + "): " + env.Safe(env.Sanitizer().Error(err)))
			rec.Decision, rec.Error = "failed", errEngineText
			resp = console.ErrResp(req.ID, ipc.CodeInternal, errEngineText)
		case refused != nil:
			rec.Decision, rec.Code = "refused", string(refused.Info.Code)
			resp = refusalResp(req.ID, refused, env)
		default:
			rec.Decision = "ok"
			// A value tool is audited by pseudonym, never by value.
			if ap, ok := result.(interface{ AuditPseudonyms() []string }); ok {
				rec.Pseudonyms = ap.AuditPseudonyms()
			}
			resp = console.OKResp(req.ID, result)
		}
		// Every call is audited before its answer leaves; one that cannot
		// be recorded is refused (fail closed).
		if err := writeAudit(env, rec); err != nil {
			return console.ErrResp(req.ID, ipc.CodeInternal, "the call could not be audited: refused")
		}
		return resp
	}
}

// errEngineText is what the agent and the audit get of an engine failure.
const errEngineText = "the log engine failed; the request did not complete"

// errCancelledText records a call whose client went away.
const errCancelledText = "cancelled: the client's connection closed"

// errLostText is what the agent and the audit get of a lost session.
const errLostText = "the log session was lost; the console reconnects at the next call"

// lost ends a call whose session is lost: the session is dropped
// (env.Lost), the call is audited and answered with ipc.CodeConnLost.
func lost(id int64, env console.Env, rec Record) ipc.Response {
	env.Lost()
	rec.Decision, rec.Error = "failed", errLostText
	if err := writeAudit(env, rec); err != nil {
		return console.ErrResp(id, ipc.CodeInternal, "the call could not be audited: refused")
	}
	return console.ErrResp(id, ipc.CodeConnLost, errLostText)
}

// errNoSessionText is what the audit gets of a call refused for want of a
// session: a fixed text (the cause is on the console, never in the audit).
const errNoSessionText = "no log session: the console could not connect"

// failed answers a call refused before the engine ran (no session, a
// failed reopen) with code and msg, after auditing it as failed with
// audited, a fixed text.
func failed(id int64, env console.Env, rec Record, code int, msg, audited string) ipc.Response {
	rec.Decision, rec.Error = "failed", audited
	if err := writeAudit(env, rec); err != nil {
		return console.ErrResp(id, ipc.CodeInternal, "the call could not be audited: refused")
	}
	return console.ErrResp(id, code, msg)
}

func refusalResp(id int64, r *Refusal, env console.Env) ipc.Response {
	info := r.Info
	msg := env.Sanitizer().Error(errors.New(r.Message))
	return ipc.Response{JSONRPC: "2.0", ID: id, Error: &ipc.RPCError{Code: ipc.CodeRefused, Message: msg, Data: &info}}
}

// writeAudit writes rec through the console's fail-closed write
// (console.Server.WriteAudit). A console without it cannot tell a failed
// write: the call is refused.
func writeAudit(env console.Env, rec Record) error {
	if w, ok := env.(interface{ WriteAudit(audit.Record) error }); ok {
		return w.WriteAudit(rec)
	}
	return errors.New("this console cannot audit its calls")
}

// checkMounts compares, in the launcher's container, the device and
// inode of .locklog and of every mount root with what the launcher checked
// on the host: a directory swapped (for a link, another directory) between
// the check and docker run is refused before anything is read.
//
// CheckMounts is exported so that the console command runs it before it
// reads .locklog at all; LoadPolicy and Connect run it again.
func CheckMounts(o Options) error {
	if !o.InContainer {
		return nil
	}
	if o.ExpectDir == "" {
		return errors.New("LOCKLOG_EXPECT_DIR is not set: start the console with the launcher")
	}
	if o.Root == "" || !filepath.IsAbs(o.Root) {
		return errors.New("no project: start the console with the launcher, from the project")
	}
	if err := expect(filepath.Join(o.Root, ".locklog"), o.ExpectDir); err != nil {
		return err
	}
	for _, e := range strings.Split(o.ExpectRoots, ";") {
		if e == "" {
			continue
		}
		di, path, ok := strings.Cut(e, " ")
		if !ok || path == "" || !strings.HasPrefix(path, "/") {
			return errors.New("LOCKLOG_EXPECT_ROOTS: malformed entry")
		}
		if err := expect(path, di); err != nil {
			return err
		}
	}
	return nil
}

// expect checks that path is a directory (not a link) with device:inode
// want.
func expect(path, want string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory (a link?): refused", path)
	}
	got, err := devIno(fi)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("%s is not the directory the launcher checked (device:inode %s, want %s): refused", path, got, want)
	}
	return nil
}

// FromEnv reads the launcher's environment into o. It does not decide
// InContainer: that is InImage, independent of the variables it checks.
func FromEnv(o Options, getenv func(string) string) Options {
	o.Network = getenv("LOCKLOG_NETWORK")
	if r := strings.Fields(getenv("LOCKLOG_EXTRA_ROOTS")); len(r) > 0 {
		o.ExtraRoots = r
	}
	o.ExpectDir = getenv("LOCKLOG_EXPECT_DIR")
	o.ExpectRoots = getenv("LOCKLOG_EXPECT_ROOTS")
	o.DockerRoot = getenv("LOCKLOG_DOCKER_ROOT")
	return o
}

// SystemFile is the separated setup's file in locklog's image.
const SystemFile = "/etc/locklog/system.toml"

// InImage reports whether this process runs in locklog's image: as the
// console account, or with the image's system file present.
// The console runs only in the launcher's container (or lock up's), which
// always passes LOCKLOG_EXPECT_DIR: a host holding the system file but
// started without the launcher is refused, by design.
func InImage(uid int, stat func(string) (os.FileInfo, error)) bool {
	if uid == product.ConsoleUID {
		return true
	}
	_, err := stat(SystemFile)
	return err == nil
}
