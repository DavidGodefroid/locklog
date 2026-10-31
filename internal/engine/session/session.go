// Package session opens the log engine of an approved policy for the
// console (logconsole.Opener): the masker of each source, the local index
// in the console's state directory, the sources the policy names (given
// only the mount roots the launcher checked), the keys (K_ref, pseudonym
// epochs), the cost model and the budgets, and serves the agent's methods
// over it.
//
// Everything it returns to the console is masked: records and counts by
// the engine, source descriptions here (field names the masker would show
// masked are left out, trusted values go through the masker).
package session

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	kconfig "github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/pii"
	"github.com/DavidGodefroid/lockkit/refusal"

	"github.com/DavidGodefroid/locklog/internal/config"
	"github.com/DavidGodefroid/locklog/internal/engine"
	"github.com/DavidGodefroid/locklog/internal/index"
	"github.com/DavidGodefroid/locklog/internal/landlock"
	"github.com/DavidGodefroid/locklog/internal/logconsole"
	"github.com/DavidGodefroid/locklog/internal/mask"
	"github.com/DavidGodefroid/locklog/internal/mountplan"
	"github.com/DavidGodefroid/locklog/internal/parse"
	"github.com/DavidGodefroid/locklog/internal/source"
	"github.com/DavidGodefroid/locklog/internal/source/docker"
	"github.com/DavidGodefroid/locklog/internal/source/file"
	"github.com/DavidGodefroid/locklog/internal/source/journald"
)

// Supported are the source kinds this build reads.
var Supported = []string{config.KindFile, config.KindJournald, config.KindDocker}

// CheckKinds refuses a profile with a source kind this build does not
// read yet (Loki): before the console confines itself or opens anything.
func CheckKinds(p config.Profile) error {
	for _, s := range p.Sources {
		if !slices.Contains(Supported, s.Kind) {
			return fmt.Errorf("profile %q: source %q is a %s source, which this build of locklog does not read yet (it reads %s): remove it from the profile, or update locklog",
				p.Name, s.Name, s.Kind, strings.Join(Supported, ", "))
		}
	}
	return nil
}

// Confinement is how the console confined itself before opening any
// source (landlock.Restrict) and whether openat2 with RESOLVE_NO_XDEV
// works: the two guards of the docker source.
type Confinement struct {
	Landlock landlock.Status
	Openat2  bool
}

// Options open a session.
type Options struct {
	logconsole.OpenOptions
	Confinement Confinement
	// FirstOpen is set on the first open of the console's process: a
	// profile with pseudonym_rotation = "session" starts a new epoch then
	// (not when the console reconnects).
	FirstOpen bool
	// EpochsOpened, when set, is called synchronously, before Open
	// returns, once the epoch store is open (and rotated, on a first open): an open that fails after it has used up
	// the first open's rotation, so the caller stops passing FirstOpen.
	EpochsOpened func()
	// Workers mask in parallel (default min(2, NumCPU): the launcher runs
	// the console with --cpus min(2, nproc)).
	Workers int
	Now     func() time.Time
	// Cost replaces the calibrated cost model (tests).
	Cost *engine.CostModel
	// MapDir replaces the docker source's map directory (tests).
	MapDir string
}

// IndexBytesPerHour is the local index building budget (design §3.3).
const IndexBytesPerHour = 20 << 30

// Session is an open engine. It implements logconsole.Engine.
type Session struct {
	eng      *engine.Engine
	maskers  *maskers
	srcs     map[string]source.Source
	names    []string
	cfg      map[string]config.Source
	epochs   *pii.EpochStore
	store    *index.Store
	conf     Confinement
	docker   bool
	notes    []string
	inflight atomic.Int64

	stop    context.CancelFunc
	indexer sync.WaitGroup
	once    sync.Once
}

var _ logconsole.Engine = (*Session)(nil)

// Open opens the engine of o.Policy.
func Open(ctx context.Context, o Options) (_ *Session, err error) {
	pr := o.Policy.Profile
	if err := CheckKinds(pr); err != nil {
		return nil, err
	}
	if o.StateDir == "" || !filepath.IsAbs(o.StateDir) {
		return nil, errors.New("no state directory for the engine")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Workers <= 0 {
		o.Workers = min(2, runtime.NumCPU())
	}
	s := &Session{srcs: map[string]source.Source{}, cfg: map[string]config.Source{}, conf: o.Confinement}
	defer func() {
		if err != nil {
			s.Close()
		}
	}()
	for _, src := range pr.Sources {
		s.cfg[src.Name] = src
		s.docker = s.docker || src.Kind == config.KindDocker
	}
	// The docker source's guards (spike S2): refused on production
	// without either.
	if s.docker {
		if err := docker.Guard(pr.Production, o.Confinement.Landlock, o.Confinement.Openat2); err != nil {
			return nil, err
		}
	}

	dir := filepath.Join(o.StateDir, "engine", kconfig.ProjectKeyOf(o.Project), pr.Name)
	fresh, err := stateDir(dir)
	if err != nil {
		return nil, err
	}
	kref, err := refKey(filepath.Join(dir, "ref.key"), fresh)
	if err != nil {
		return nil, err
	}
	sealer, err := engine.NewSealer(kref)
	clear(kref)
	if err != nil {
		return nil, err
	}
	if s.epochs, err = openEpochs(filepath.Join(dir, "epochs"), fresh, pr, o.FirstOpen, o.Now(), o.EpochsOpened); err != nil {
		return nil, err
	}
	rules, notes, err := loadRules(o.Project, filepath.Join(dir, "pii"))
	if err != nil {
		return nil, err
	}
	s.notes = notes
	values, err := valueDetectors(pr.Detectors)
	if err != nil {
		return nil, err
	}
	if s.maskers, err = newMaskers(pr, rules, values, s.epochs.Current()); err != nil {
		return nil, err
	}
	if s.store, err = index.Open(filepath.Join(dir, "index")); err != nil {
		return nil, err
	}

	// Sources last: nothing is read before the keys, the rules and the
	// masker are in place.
	for _, src := range pr.Sources {
		ss, err := s.openSource(src, o)
		if err != nil {
			return nil, fmt.Errorf("source %s: %w", src.Name, err)
		}
		s.srcs[src.Name] = ss
		s.names = append(s.names, src.Name)
	}
	slices.Sort(s.names)

	cost := o.Cost
	if cost == nil {
		p, err := parse.New(parse.Options{})
		if err != nil {
			return nil, err
		}
		base := s.maskers.base
		cost = engine.NewCostModel(p, func(ev parse.Event) { base.Mask("", ev) }, o.Workers, o.Now)
	}
	fp := o.Policy.Fingerprint()
	s.eng, err = engine.New(engine.Options{
		Sources:    s.srcs,
		Trusted:    s.trusted,
		Masker:     s.maskers,
		Sealer:     sealer,
		Cost:       cost,
		PolicyFP:   func() string { return fp },
		Detect:     func(v string) bool { return s.maskers.base.Text(v) != v },
		NameMasked: s.maskers.nameMasked,
		Limits:     limits(pr.Limits),
		Prefilter:  pr.Prefilter,
		Workers:    o.Workers,
		Now:        o.Now,
	})
	if err != nil {
		return nil, err
	}
	s.startIndexer()
	return s, nil
}

// stateDir creates dir (0700) and reports whether it is new.
func stateDir(dir string) (bool, error) {
	fi, err := os.Lstat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return false, fmt.Errorf("engine state: %w", err)
		}
		return true, nil
	case err != nil:
		return false, fmt.Errorf("engine state: %w", err)
	case !fi.IsDir():
		return false, fmt.Errorf("engine state %s is not a directory", dir)
	case runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0:
		return false, fmt.Errorf("engine state %s is accessible to others (mode %v); want 0700", dir, fi.Mode().Perm())
	}
	return false, nil
}

// refKey reads K_ref (32 bytes, 0600), creating it only in a new state
// directory: a missing or corrupt key otherwise refuses the start (design
// §5.6), as the references and cursors sealed under it would silently die.
func refKey(p string, create bool) ([]byte, error) {
	fi, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		if !create {
			return nil, fmt.Errorf("the engine key %s is missing: the console's state is incomplete (restore the home volume, or remove the profile's engine state to start afresh)", p)
		}
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if err := writePrivate(p, key); err != nil {
			return nil, err
		}
		return key, nil
	}
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("the engine key %s is not a private file (0600): refused", p)
	}
	key, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		clear(key)
		return nil, fmt.Errorf("the engine key %s is corrupt: refused", p)
	}
	return key, nil
}

func writePrivate(p string, data []byte) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(p)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(p)
		return err
	}
	return f.Close()
}

// openEpochs opens the pseudonym epochs (created only in a new state
// directory), rotates them as the profile says and prunes the keys older
// than pseudonym_max_age.
func openEpochs(dir string, create bool, pr config.Profile, first bool, now time.Time, opened func()) (*pii.EpochStore, error) {
	st, err := pii.OpenEpochStore(dir, create, now)
	if errors.Is(err, pii.ErrNoEpoch) {
		return nil, fmt.Errorf("the pseudonym epoch keys of profile %q are missing: refused (locklog keys rotate starts a new epoch)", pr.Name)
	}
	if err != nil {
		return nil, err
	}
	rotate := false
	switch {
	case pr.PseudonymRotation == config.RotationSession:
		rotate = first && !create
	case pr.RotationEvery() > 0:
		rotate = st.RotationDue(now, pr.RotationEvery())
	}
	if rotate {
		if _, err := st.Rotate(now); err != nil {
			st.Close()
			return nil, err
		}
	}
	// From here the first open's rotation is used up, even if pruning
	// or a later step fails.
	if opened != nil {
		opened()
	}
	if pr.PseudonymMaxAge > 0 {
		if _, err := st.Prune(now, pr.PseudonymMaxAge); err != nil {
			st.Close()
			return nil, err
		}
	}
	return st, nil
}

// loadRules reads the human's rules: the project's .locklog/pii.toml
// (names and modes) and the console's value rules and agent rules (its PII
// directory, in the home volume). The project's allow rules loosen the
// masking without the console's review: they are not applied (notes says
// so on :status).
func loadRules(project, piiDir string) (*mask.Rules, []string, error) {
	var notes []string
	r := &mask.Rules{}
	if project != "" {
		pr, err := mask.LoadProjectRules(filepath.Join(project, ".locklog", "pii.toml"))
		if err != nil {
			return nil, nil, err
		}
		r.Mask = pr.Mask
		if len(pr.Allow) > 0 {
			notes = append(notes, fmt.Sprintf("%d allow rule(s) of .locklog/pii.toml not applied: an allow rule loosens the masking and is not part of the reviewed policy yet", len(pr.Allow)))
		}
	}
	if err := os.MkdirAll(piiDir, 0o700); err != nil {
		return nil, nil, err
	}
	vs, err := mask.LoadValueRules(piiDir)
	if err != nil {
		return nil, nil, err
	}
	r.Values = vs
	if r.Agent, err = mask.OpenAgentRules(piiDir); err != nil {
		return nil, nil, err
	}
	return r, notes, nil
}

// valueDetectors are the profile's value detectors (step 4); none named
// takes the masker's default set.
func valueDetectors(names []string) (mask.Finder, error) {
	if len(names) == 0 {
		return nil, nil
	}
	ds, err := mask.ValueDetectors(names)
	if err != nil {
		return nil, err
	}
	return ds, nil
}

// limits are the engine's per-call budgets from the profile's.
func limits(l config.Limits) engine.Limits {
	d := engine.DefaultLimits()
	return engine.Limits{
		LocalRange: l.Local.Range, RemoteRange: l.Remote.Range,
		// Only local sources are read: the count range is the local one.
		CountRange: l.Local.CountRange,
		LocalBytes: l.Local.MaxBytes, RemoteBytes: l.Remote.MaxBytes,
		MaxRecords: l.MaxRecords, MaxOutput: int(l.MaxOutputBytes),
		Deadline: d.Deadline,
	}
}

// attrKeys are the attribute keys of a source's events: the frame keys of
// a framed format (and of the docker source), and the docker source's
// static container name.
func attrKeys(s config.Source) []string {
	switch {
	case s.Kind == config.KindDocker:
		return append(slices.Clone(parse.FrameKeys), docker.ContainerField)
	case s.Format == "cri" || s.Format == "docker-json":
		return slices.Clone(parse.FrameKeys)
	}
	return nil
}

// isLabel reports whether a trusted name of s is a label (an attribute).
func isLabel(s config.Source, name string) bool {
	head, _, _ := strings.Cut(name, ".")
	return slices.Contains(attrKeys(s), head)
}

// trustedNames are the trusted names of s: its line fields and its labels.
func trustedNames(s config.Source) (fields, labels []string) {
	for _, f := range s.TrustedFields() {
		if isLabel(s, f) {
			labels = append(labels, f)
		} else {
			fields = append(fields, f)
		}
	}
	if s.Kind == config.KindDocker && !slices.Contains(labels, docker.ContainerField) {
		labels = append(labels, docker.ContainerField)
	}
	return fields, labels
}

// trusted implements engine.Options.Trusted.
func (s *Session) trusted(src, name string, label bool) bool {
	c, ok := s.cfg[src]
	if !ok {
		return false
	}
	fields, labels := trustedNames(c)
	if label {
		return slices.Contains(labels, name)
	}
	return slices.Contains(fields, name)
}

func (s *Session) openSource(c config.Source, o Options) (source.Source, error) {
	m := s.maskers.of(c.Name)
	sensitive := func(f, v string) bool { return m.TrustedValue(c.Name, f, v) != v }
	switch c.Kind {
	case config.KindFile:
		var roots []string
		for _, g := range c.Paths {
			d := path.Clean(mountplan.Dir(g))
			if !slices.Contains(o.Roots.Dirs, d) {
				return nil, fmt.Errorf("%s is not a checked mount root", d)
			}
			if !slices.Contains(roots, d) {
				roots = append(roots, d)
			}
		}
		p, err := parse.New(parse.Options{Format: c.Format, Multiline: c.Multiline})
		if err != nil {
			return nil, err
		}
		var keys []string
		for _, f := range c.TrustedFields() {
			keys = append(keys, index.TermKey(f, isLabel(c, f)))
		}
		return file.New(file.Options{Name: c.Name, Paths: c.Paths, Recursive: c.Recursive, Roots: roots, Parser: p,
			Trusted: keys, Index: s.store, Sensitive: sensitive, Now: o.Now})
	case config.KindJournald:
		if len(o.Roots.Journal) == 0 {
			return nil, errors.New("no checked journal directory")
		}
		p, err := parse.New(parse.Options{Format: c.Format, Multiline: c.Multiline})
		if err != nil {
			return nil, err
		}
		return journald.New(journald.Options{Name: c.Name, Roots: slices.Clone(o.Roots.Journal), Units: c.Units,
			Trusted: c.Trusted, Allow: c.Allow, UserJournals: o.Policy.Profile.UserJournals, Parser: p, Now: o.Now})
	case config.KindDocker:
		do, err := docker.FromConfig(c)
		if err != nil {
			return nil, err
		}
		if o.Roots.Docker == "" || do.Root != o.Roots.Docker {
			return nil, errors.New("the containers root is not the checked one")
		}
		if o.MapDir != "" {
			do.MapDir = o.MapDir
		}
		do.Index, do.Sensitive, do.Now = s.store, sensitive, o.Now
		return docker.New(do)
	}
	return nil, fmt.Errorf("unsupported source kind %q", c.Kind)
}

// startIndexer builds the local index in the background (backfill first,
// under its own budget; the upkeep of grown tails waits while agent calls
// run).
func (s *Session) startIndexer() {
	var ixs []index.Indexer
	for _, n := range s.names {
		if ix, ok := s.srcs[n].(index.Indexer); ok {
			ixs = append(ixs, ix)
		}
	}
	if len(ixs) == 0 {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.stop = cancel
	s.indexer.Add(1)
	go func() {
		defer s.indexer.Done()
		index.Run(ctx, ixs, index.RunOptions{BytesPerHour: IndexBytesPerHour, Busy: func() bool { return s.inflight.Load() > 0 },
			Flush: s.store.Flush})
	}()
}

// Close stops the indexer, saves the index and releases the epoch store.
func (s *Session) Close() error {
	var err error
	s.once.Do(func() {
		if s.stop != nil {
			s.stop()
			s.indexer.Wait()
		}
		if s.store != nil {
			err = s.store.Flush()
		}
		if s.epochs != nil {
			if e := s.epochs.Close(); err == nil {
				err = e
			}
		}
	})
	return err
}

// Handle implements logconsole.Engine.
func (s *Session) Handle(ctx context.Context, method string, params json.RawMessage, _ logconsole.Caller) (any, *logconsole.Refusal, error) {
	s.inflight.Add(1)
	defer s.inflight.Add(-1)
	switch method {
	case logconsole.MethodStatus:
		if r := noParams(params); r != nil {
			return nil, r, nil
		}
		return s.Status(ctx), nil, nil
	case logconsole.MethodSources:
		if r := noParams(params); r != nil {
			return nil, r, nil
		}
		return s.describe(ctx), nil, nil
	}
	res, ref, err := s.eng.Handle(ctx, method, params)
	if ref != nil {
		return nil, refusalOf(ref), nil
	}
	return res, nil, err
}

// noParams refuses parameters to a method that takes none.
func noParams(params json.RawMessage) *logconsole.Refusal {
	var m map[string]json.RawMessage
	if json.Unmarshal(params, &m) != nil || len(m) > 0 {
		return refusalOf(&engine.Error{Code: engine.EBadQuery, Message: "this method takes no parameters"})
	}
	return nil
}

// retries says what the agent may do after each engine refusal.
var retries = map[string]refusal.Retry{
	engine.EBadQuery: refusal.RetryRewrite, engine.EUnknownField: refusal.RetryRewrite, engine.EPIIInQuery: refusal.RetryRewrite,
	engine.EOverBudget: refusal.RetryRewrite, engine.EPolicyChanged: refusal.RetryRewrite, engine.EStale: refusal.RetryRewrite,
	engine.ESource: refusal.RetryStop, engine.EMask: refusal.RetryStop,
}

// hints are the default rewrite hints.
var hints = map[string]string{
	engine.EOverBudget:    "narrow the range or the sources, or count on trusted fields first",
	engine.EPolicyChanged: "the approved policy changed: run the query again without the cursor or ref",
	engine.EStale:         "run the query again",
	engine.EPIIInQuery:    "address personal values by their pseudonym (⟦kind:ID⟧) as the records show them",
	engine.EUnknownField:  "use a field name the records or log.sources show",
}

// refusalOf is the console's form of an engine refusal. Its text holds no
// log content (engine.Error); the estimate is plan-based.
func refusalOf(e *engine.Error) *logconsole.Refusal {
	msg := e.Message
	if e.Span != "" {
		msg += " (at " + e.Span + ")"
	}
	if e.Estimate != nil {
		msg += fmt.Sprintf(" (estimate: %d bytes in %d granules over %s)", e.Estimate.Bytes, e.Estimate.Granules, config.FormatDuration(e.Estimate.Range))
	}
	retry, ok := retries[e.Code]
	if !ok {
		retry = refusal.RetryStop
	}
	return &logconsole.Refusal{Message: msg, Info: refusal.Info{Code: refusal.Code(e.Code), Retry: retry, Hint: hints[e.Code]}}
}

// Status is the engine's part of log.status and :status: no log content.
type Status struct {
	Epoch   string         `json:"epoch"`
	Sources []SourceStatus `json:"sources"`
	// Landlock is the console's confinement ("landlock enforced (ABI 5)").
	Landlock string `json:"landlock"`
	// Residuals name the docker source's missing guards.
	Residuals []string `json:"residuals,omitempty"`
	Notes     []string `json:"notes,omitempty"`
}

// SourceStatus names one source.
type SourceStatus struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// Status implements logconsole.Engine.
func (s *Session) Status(context.Context) any {
	st := Status{Epoch: s.maskers.base.Epoch(), Landlock: s.conf.Landlock.String(), Notes: s.notes}
	for _, n := range s.names {
		st.Sources = append(st.Sources, SourceStatus{Name: n, Kind: s.srcs[n].Kind()})
	}
	if s.docker {
		st.Residuals = docker.Residuals(s.conf.Landlock, s.conf.Openat2)
	}
	return st
}

// SourceInfo is one source of log.sources, masked.
type SourceInfo struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Format  string `json:"format,omitempty"`
	Streams int    `json:"streams"`
	Bytes   int64  `json:"bytes"`
	// Oldest and Newest bound the records, when known.
	Oldest      *time.Time `json:"oldest,omitempty"`
	Newest      *time.Time `json:"newest,omitempty"`
	IndexedFrom *time.Time `json:"indexed_from,omitempty"`
	Fields      []Field    `json:"fields"`
	// MaskedFields counts the field names left out: the masker shows them
	// masked (⟦key:ID⟧), as the records do.
	MaskedFields int `json:"masked_fields,omitempty"`
	// Error is set when the source could not be described (no detail:
	// its error may name files).
	Error string `json:"error,omitempty"`
}

// Field is one field of a source.
type Field struct {
	Name    string   `json:"name"`
	Label   bool     `json:"label,omitempty"`
	Trusted bool     `json:"trusted,omitempty"`
	Values  []string `json:"values,omitempty"`
}

// Sources is the answer of log.sources.
type Sources struct {
	Epoch   string       `json:"epoch"`
	Sources []SourceInfo `json:"sources"`
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// describe is log.sources: every name and value masked.
func (s *Session) describe(ctx context.Context) Sources {
	out := Sources{Epoch: s.maskers.base.Epoch()}
	for _, n := range s.names {
		src := s.srcs[n]
		info := SourceInfo{Name: n, Kind: src.Kind()}
		sch, err := src.Describe(ctx)
		if err != nil {
			info.Error = "the source could not be described"
			out.Sources = append(out.Sources, info)
			continue
		}
		info.Format, info.Streams, info.Bytes = sch.Format, sch.Streams, sch.Bytes
		info.Oldest, info.Newest, info.IndexedFrom = timePtr(sch.Oldest), timePtr(sch.Newest), timePtr(sch.IndexedFrom)
		m := s.maskers.of(n)
		for _, f := range sch.Fields {
			if s.maskers.nameMasked(n, f.Name) {
				info.MaskedFields++
				continue
			}
			fl := Field{Name: f.Name, Label: f.Label, Trusted: f.Trusted}
			for _, v := range f.Values {
				fl.Values = append(fl.Values, m.TrustedValue(n, f.Name, v))
			}
			info.Fields = append(info.Fields, fl)
		}
		out.Sources = append(out.Sources, info)
	}
	return out
}
