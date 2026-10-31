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
	"os"
	"slices"
	"strings"
	"sync"

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
)

// Methods lists the methods served, in a fixed order.
var Methods = []string{MethodStatus, MethodSources, MethodSearch, MethodCount}

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
}

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
	// InContainer is true in the launcher's container (LOCKLOG_EXPECT_*
	// are then required).
	InContainer bool
	// SysClassNet is /sys/class/net (tests replace it).
	SysClassNet string
	Open        Opener
}

// Backend implements console.Backend.
type Backend struct {
	o Options

	mu  sync.Mutex
	cur *session
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
		cp.Host = s.Remote.URL
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
}

func (s *session) Close() error { return s.engine.Close() }

// Connect implements console.Backend: the launcher's checks first, then
// the engine of the policy in force.
func (b *Backend) Connect(ctx context.Context, c console.Credentials) (console.Session, error) {
	pol, ok := c.Policy.(Policy)
	if !ok {
		return nil, errors.New("no approved locklog policy to connect to")
	}
	if err := b.checkMounts(); err != nil {
		return nil, err
	}
	if b.o.Open == nil {
		return nil, errors.New("this build has no log engine")
	}
	var creds egress.Credentials
	if c.Secret != nil {
		creds = egress.Credentials{User: c.User, Secret: string(c.Secret)}
	}
	e, err := b.o.Open(ctx, OpenOptions{Policy: pol.Policy, Credentials: creds, StateDir: b.o.StateDir})
	if err != nil {
		return nil, err
	}
	s := &session{engine: e, policy: pol}
	b.mu.Lock()
	b.cur = s
	b.mu.Unlock()
	return s, nil
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
		return []console.Finding{{Refuse: true, Text: "cannot list the network interfaces: " + err.Error()}}
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
		var c Caller
		if cred, ok := console.PeerFrom(ctx); ok {
			c = Caller{UID: cred.UID, PID: cred.PID}
		}
		sess, err := env.Session(ctx)
		if err != nil {
			return console.ErrResp(req.ID, ipc.CodeConnLost, env.Sanitizer().Error(err))
		}
		ls, ok := console.Unwrap(sess).(*session)
		if !ok {
			return console.ErrResp(req.ID, ipc.CodeInternal, "no log engine")
		}
		params := req.Params
		if len(params) == 0 {
			params = json.RawMessage("{}")
		}
		result, refused, err := ls.engine.Handle(ctx, method, params, c)
		rec := newRecord(ctx, env, method, params)
		var resp ipc.Response
		switch {
		case err != nil:
			msg := env.Sanitizer().Error(err)
			rec.Decision, rec.Error = "failed", msg
			resp = console.ErrResp(req.ID, ipc.CodeInternal, msg)
		case refused != nil:
			rec.Decision, rec.Code = "refused", string(refused.Info.Code)
			resp = refusalResp(req.ID, refused)
		default:
			rec.Decision = "ok"
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

func refusalResp(id int64, r *Refusal) ipc.Response {
	info := r.Info
	return ipc.Response{JSONRPC: "2.0", ID: id, Error: &ipc.RPCError{Code: ipc.CodeRefused, Message: r.Message, Data: &info}}
}

// writeAudit writes rec through the console's fail-closed write when it
// has one (console.Server), else through Env.Audit.
func writeAudit(env console.Env, rec Record) error {
	if w, ok := env.(interface{ WriteAudit(audit.Record) error }); ok {
		return w.WriteAudit(rec)
	}
	env.Audit(rec)
	return nil
}

// checkMounts compares, in the launcher's container, the device and
// inode of .locklog and of every mount root with what the launcher checked
// on the host: a directory swapped (for a link, another directory) between
// the check and docker run is refused before anything is read.
func (b *Backend) checkMounts() error {
	if !b.o.InContainer {
		return nil
	}
	if b.o.ExpectDir == "" {
		return errors.New("LOCKLOG_EXPECT_DIR is not set: start the console with the launcher")
	}
	if err := expect(b.o.Root+"/.locklog", b.o.ExpectDir); err != nil {
		return err
	}
	for _, e := range strings.Split(b.o.ExpectRoots, ";") {
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

// FromEnv reads the launcher's environment into o.
func FromEnv(o Options, getenv func(string) string) Options {
	o.Network = getenv("LOCKLOG_NETWORK")
	if r := strings.Fields(getenv("LOCKLOG_EXTRA_ROOTS")); len(r) > 0 {
		o.ExtraRoots = r
	}
	o.ExpectDir = getenv("LOCKLOG_EXPECT_DIR")
	o.ExpectRoots = getenv("LOCKLOG_EXPECT_ROOTS")
	o.InContainer = o.ExpectDir != "" || o.ExpectRoots != ""
	return o
}
