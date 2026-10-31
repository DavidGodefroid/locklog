// Package docker is the Docker log source: the json-file logs of the
// containers whose names the human approved, read from the containers root
// (`docker info .DockerRootDir` + /containers, bound read-only and
// non-recursive by the launcher), through a name -> id map the launcher keeps
// current.
//
// # The map
//
// The launcher writes the map into a host directory bound read-only, as a
// directory, at /run/locklog-map (MapDir). Each version is a file
// "map.v<N>" (N decimal, from 1, no leading zero) written atomically; the
// newest valid version wins. A version is:
//
//	locklog-map 1
//	c <id> <name> <max_file> <compress>
//	x <id>
//
// one entry per line, fields separated by one space, every line ending with
// "\n". A "c" line maps a json-file container: its 64 lower-case hex id, its
// name (a container name the config accepts), its max-file (1..100) and
// whether rotated files are compressed (0 or 1). An "x" line names a locklog
// console container (by its label or its name prefix): never served. Any
// malformed line, a duplicate id or name, refuses that version, and then
// nothing is served (fail closed: an older version is never used instead).
//
// # What is served
//
// Whatever the map says, a container is served only when its name matches one
// of the source's approved globs (path.Match: '*' and '?'), its name does not
// start with config.ConsolePrefix, and its id is neither an "x" id nor the
// console's own. Of a served container, only <Root>/<id>/<id>-json.log and
// <id>-json.log.N (.N.gz when compressed; .1 while Docker has not gzipped it
// yet), 1 <= N < max_file, are opened:
// probed by name (the 0710 directories cannot be listed with gid 0), beneath
// the root, never across a mount point (file.Options.NoXDev). Every record
// carries the trusted field "container" (the name).
//
// Streams are "<id>/<name>/<file stream>": a renamed container's earlier
// references are stale.
package docker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DavidGodefroid/locklog/internal/config"
	"github.com/DavidGodefroid/locklog/internal/index"
	"github.com/DavidGodefroid/locklog/internal/parse"
	"github.com/DavidGodefroid/locklog/internal/source"
	"github.com/DavidGodefroid/locklog/internal/source/file"
)

const (
	// Kind is the source kind.
	Kind = "docker"
	// DefaultMapDir is where the launcher binds the map directory.
	DefaultMapDir = "/run/locklog-map"
	// RootEnv names the environment variable the launcher sets to the
	// containers root, bound at its own path.
	RootEnv = "LOCKLOG_DOCKER_ROOT"
	// ContainerField is the trusted field holding the container name.
	ContainerField = "container"
	// mapTTL is how long a map listing is reused.
	mapTTL = 2 * time.Second
)

// Options configure a docker source.
type Options struct {
	Name string
	// Containers are the approved container name globs.
	Containers []string
	// Attrs are the json-file attrs kept (as "attrs.<key>"); others are
	// dropped.
	Attrs []string
	// Root is the containers root, as mounted (absolute).
	Root string
	// MapDir is the map directory (default DefaultMapDir).
	MapDir string
	// Parse is the base of the parser options (multiline, location);
	// the format and the attributes are set by the source.
	Parse parse.Options
	// Trusted are the trusted names the index counts; ContainerField is
	// always added. The container, the stream and attrs.<key> are labels
	// (frame attributes, parse.Event.Attrs), the others line fields.
	Trusted []string
	// Index is the local index store (nil: no index).
	Index *index.Store
	// Sensitive reports a trusted value a detector flags.
	Sensitive func(field, value string) bool
	// Now is the clock (tests).
	Now func() time.Time
	// Self returns the ids of the console's own container (full, or
	// prefixes of at least 12 characters); default SelfIDs. Called once.
	Self func() []string
}

// FromConfig returns the options of a configured docker source; the root
// comes from RootEnv. The caller sets Index, Sensitive and Parse.Location.
func FromConfig(s config.Source) (Options, error) {
	if s.Kind != config.KindDocker {
		return Options{}, fmt.Errorf("source %q is not a docker source", s.Name)
	}
	root := os.Getenv(RootEnv)
	if root == "" {
		return Options{}, fmt.Errorf("docker source %q: %s is not set (start the console with the launcher)", s.Name, RootEnv)
	}
	return Options{Name: s.Name, Containers: s.Containers, Attrs: s.Attrs, Root: root, MapDir: DefaultMapDir,
		Parse: parse.Options{Multiline: s.Multiline}, Trusted: s.TrustedFields()}, nil
}

// Source is a docker source. It is safe for concurrent use.
type Source struct {
	opts Options
	self []string

	mu      sync.Mutex
	mapKey  string
	mapTime time.Time
	conts   map[string]*cont // served containers, by id
}

// cont is one served container and its file source.
type cont struct {
	c   Container
	src *file.Source
}

// New validates opts.
func New(opts Options) (*Source, error) {
	if opts.Name == "" {
		return nil, errors.New("docker source: no name")
	}
	if len(opts.Containers) == 0 {
		return nil, errors.New("docker source: no container globs")
	}
	for _, g := range opts.Containers {
		if g == "" || strings.ContainsAny(g, "[\\/") {
			return nil, fmt.Errorf("docker source: invalid container glob %q", g)
		}
		if _, err := path.Match(g, ""); err != nil {
			return nil, fmt.Errorf("docker source: invalid container glob %q", g)
		}
	}
	if !path.IsAbs(opts.Root) || path.Clean(opts.Root) != opts.Root || opts.Root == "/" {
		return nil, fmt.Errorf("docker source: the containers root %q is not an absolute, clean path", opts.Root)
	}
	if opts.MapDir == "" {
		opts.MapDir = DefaultMapDir
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Self == nil {
		opts.Self = SelfIDs
	}
	opts.Containers = slices.Clone(opts.Containers)
	opts.Attrs = slices.Clone(opts.Attrs)
	opts.Trusted = trustedKeys(opts.Trusted)
	// The parser options are checked once here.
	if _, err := parse.New(parserOptions(opts, "x")); err != nil {
		return nil, fmt.Errorf("docker source: %w", err)
	}
	var self []string
	for _, id := range opts.Self() {
		if len(id) >= 12 {
			self = append(self, id)
		}
	}
	return &Source{opts: opts, self: self, conts: map[string]*cont{}}, nil
}

// trustedKeys returns the indexed names (index.TermKey) of the trusted
// names, ContainerField added, sorted: the container and the frame keys
// (parse.FrameKeys) are labels.
func trustedKeys(trusted []string) []string {
	out := []string{index.LabelKey(ContainerField)}
	for _, f := range trusted {
		out = append(out, index.TermKey(f, IsLabel(f)))
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// IsLabel reports whether a trusted name of a docker source is a label:
// the container, the runtime's stream, an attrs.<key>.
func IsLabel(name string) bool {
	head, _, _ := strings.Cut(name, ".")
	return name == ContainerField || slices.Contains(parse.FrameKeys, head)
}

func parserOptions(opts Options, name string) parse.Options {
	po := opts.Parse
	po.Format = "docker-json"
	po.FrameAttrs = opts.Attrs
	po.StaticAttrs = []parse.Member{{Key: ContainerField, Value: parse.Value{Kind: parse.KindString, Str: name}}}
	return po
}

// Name returns the source name.
func (s *Source) Name() string { return s.opts.Name }

// Kind returns "docker".
func (s *Source) Kind() string { return Kind }

// approved reports whether a mapped container may be served: the read-time
// filter, whatever the map says.
func (s *Source) approved(c Container, consoles map[string]bool) bool {
	if !config.ValidContainerName(c.Name) || strings.HasPrefix(c.Name, config.ConsolePrefix) {
		return false
	}
	if consoles[c.ID] || isSelf(s.self, c.ID) {
		return false
	}
	for _, g := range s.opts.Containers {
		if ok, _ := path.Match(g, c.Name); ok {
			return true
		}
	}
	return false
}

// paths returns the literal paths of a container's log files, and the
// alternates: with compression, Docker gzips <id>-json.log.1 in the
// background, so .1 is read while it exists, else .1.gz (a .1.gz beside a .1
// is still being written).
func (s *Source) paths(c Container) ([]string, map[string]string) {
	base := s.opts.Root + "/" + c.ID + "/" + c.ID + "-json.log"
	out := []string{base}
	alt := map[string]string{}
	for n := 1; n < c.MaxFile; n++ {
		p := base + "." + strconv.Itoa(n)
		switch {
		case !c.Compress:
		case n == 1:
			alt[p] = p + ".gz"
		default:
			p += ".gz"
		}
		out = append(out, p)
	}
	return out, alt
}

// containers returns the served containers, sorted by name, re-reading the
// map when it changed.
func (s *Source) containers() ([]*cont, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.opts.Now()
	if s.mapTime.IsZero() || now.Sub(s.mapTime) >= mapTTL || now.Before(s.mapTime) {
		s.mapTime = now
		names, key := mapFiles(s.opts.MapDir)
		if key != s.mapKey || key == "" {
			s.mapKey = key
			m, ok := readNewest(s.opts.MapDir, names)
			if !ok {
				m = Map{}
			}
			if err := s.apply(m); err != nil {
				return nil, err
			}
		}
	}
	out := make([]*cont, 0, len(s.conts))
	for _, c := range s.conts {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].c.Name < out[j].c.Name })
	return out, nil
}

// apply makes m's approved containers the served ones: new ones get a file
// source, changed ones (renamed, other max-file or compression) a new one,
// gone ones are dropped.
func (s *Source) apply(m Map) error {
	next := map[string]*cont{}
	for _, c := range m.Containers {
		if !s.approved(c, m.Consoles) {
			continue
		}
		if old, ok := s.conts[c.ID]; ok && old.c == c {
			next[c.ID] = old
			continue
		}
		cs, err := s.newCont(c)
		if err != nil {
			return err
		}
		next[c.ID] = cs
	}
	s.conts = next
	return nil
}

func (s *Source) newCont(c Container) (*cont, error) {
	fo, err := s.fileOptions(c)
	if err != nil {
		return nil, err
	}
	src, err := file.New(fo)
	if err != nil {
		return nil, fmt.Errorf("docker source: %w", err)
	}
	return &cont{c: c, src: src}, nil
}

// fileOptions are the options of a container's file source: its literal
// paths only, beneath the root, never across a mount point (NoXDev, always),
// the index tagged with the name every record carries (a renamed
// container's granules, counted under the old name, are rebuilt, also
// across a restart or a rename through a name that is not served).
func (s *Source) fileOptions(c Container) (file.Options, error) {
	p, err := parse.New(parserOptions(s.opts, c.Name))
	if err != nil {
		return file.Options{}, fmt.Errorf("docker source: %w", err)
	}
	paths, alt := s.paths(c)
	return file.Options{Name: s.opts.Name, Paths: paths, Alternates: alt, Roots: []string{s.opts.Root}, Parser: p,
		Trusted: s.opts.Trusted, Index: s.opts.Index, Sensitive: s.opts.Sensitive, Now: s.opts.Now, NoXDev: true, Tag: c.Name}, nil
}

// byStream returns the served container of a stream, checking its name.
func (s *Source) byStream(stream string) (*cont, string, error) {
	id, rest, ok := strings.Cut(stream, "/")
	if !ok {
		return nil, "", source.ErrNotFound
	}
	name, inner, ok := strings.Cut(rest, "/")
	if !ok || !validID(id) {
		return nil, "", source.ErrNotFound
	}
	cs, err := s.containers()
	if err != nil {
		return nil, "", err
	}
	for _, c := range cs {
		if c.c.ID == id {
			if c.c.Name != name {
				return nil, "", source.ErrStale
			}
			return c, inner, nil
		}
	}
	return nil, "", source.ErrNotFound
}

func wrap(c *cont, inner string) string { return c.c.ID + "/" + c.c.Name + "/" + inner }

func (s *Source) wrapPlan(c *cont, p source.Byteplan) []source.Chunk {
	out := make([]source.Chunk, len(p.Chunks))
	for i, ch := range p.Chunks {
		ch.Source = s.opts.Name
		ch.Stream = wrap(c, ch.Stream)
		out[i] = ch
	}
	return out
}

func (s *Source) wrapRecord(c *cont, r source.RawRecord) source.RawRecord {
	r.Ref.Source = s.opts.Name
	r.Ref.Stream = wrap(c, r.Ref.Stream)
	return r
}

// selected returns the containers whose name satisfies sel's terms on the
// ContainerField label (other terms are left to the file sources). The
// agent sees a name a detector flags as a pseudonym, never in clear: such a
// container, and a term holding a placeholder, may match and are kept (the
// engine evaluates every term after masking), as the index does with a
// redacted value.
func (s *Source) selected(cs []*cont, sel source.Selector) []*cont {
	var terms []source.Term
	for _, t := range sel.Terms {
		if t.Label && t.Field == ContainerField && !slices.ContainsFunc(t.Values, func(v string) bool { return strings.Contains(v, "⟦") }) {
			terms = append(terms, t)
		}
	}
	if len(terms) == 0 {
		return cs
	}
	ts := source.Selector{Terms: terms}
	var out []*cont
	for _, c := range cs {
		if (s.opts.Sensitive != nil && s.opts.Sensitive(ContainerField, c.c.Name)) || ts.Match(nil, map[string]string{ContainerField: c.c.Name}) {
			out = append(out, c)
		}
	}
	return out
}

// Plan returns the chunks of the served containers matching sel, container
// by container (sorted by name), each newest stream first.
func (s *Source) Plan(ctx context.Context, r source.Range, sel source.Selector) (source.Byteplan, error) {
	cs, err := s.containers()
	if err != nil {
		return source.Byteplan{}, err
	}
	var plan source.Byteplan
	for _, c := range s.selected(cs, sel) {
		p, err := c.src.Plan(ctx, r, sel)
		if err != nil {
			return source.Byteplan{}, err
		}
		plan.Chunks = append(plan.Chunks, s.wrapPlan(c, p)...)
	}
	return plan, nil
}

// Scan returns the records of a chunk.
func (s *Source) Scan(ctx context.Context, ch source.Chunk) (source.Iterator, error) {
	c, inner, err := s.byStream(ch.Stream)
	if err != nil {
		return nil, err
	}
	ich := ch
	ich.Stream = inner
	it, err := c.src.Scan(ctx, ich)
	if err != nil {
		return nil, err
	}
	return &iter{s: s, c: c, it: it}, nil
}

type iter struct {
	s  *Source
	c  *cont
	it source.Iterator
}

func (it *iter) Next() (source.RawRecord, error) {
	r, err := it.it.Next()
	if err != nil {
		return source.RawRecord{}, err
	}
	return it.s.wrapRecord(it.c, r), nil
}

func (it *iter) Processed() int64 { return it.it.Processed() }
func (it *iter) Close() error     { return it.it.Close() }

// Reread returns the record at ref.
func (s *Source) Reread(ctx context.Context, ref source.RawRef) (source.RawRecord, error) {
	c, inner, err := s.byStream(ref.Stream)
	if err != nil {
		return source.RawRecord{}, err
	}
	iref := ref
	iref.Stream = inner
	r, err := c.src.Reread(ctx, iref)
	if err != nil {
		return source.RawRecord{}, err
	}
	return s.wrapRecord(c, r), nil
}

// AroundMeasured is Around, also returning the bytes the inner file source
// processed (source.AroundMeter).
func (s *Source) AroundMeasured(ctx context.Context, ref source.RawRef, before, after int) ([]source.RawRecord, int64, error) {
	c, inner, err := s.byStream(ref.Stream)
	if err != nil {
		return nil, 0, err
	}
	iref := ref
	iref.Stream = inner
	rs, n, err := c.src.AroundMeasured(ctx, iref, before, after)
	if err != nil {
		return nil, n, err
	}
	for i := range rs {
		rs[i] = s.wrapRecord(c, rs[i])
	}
	return rs, n, nil
}

// Around returns the records around ref, from its stream.
func (s *Source) Around(ctx context.Context, ref source.RawRef, before, after int) ([]source.RawRecord, error) {
	c, inner, err := s.byStream(ref.Stream)
	if err != nil {
		return nil, err
	}
	iref := ref
	iref.Stream = inner
	rs, err := c.src.Around(ctx, iref, before, after)
	if err != nil {
		return nil, err
	}
	for i := range rs {
		rs[i] = s.wrapRecord(c, rs[i])
	}
	return rs, nil
}

// Describe merges the served containers' schemas. The container field's
// values are the served names.
func (s *Source) Describe(ctx context.Context) (source.Schema, error) {
	cs, err := s.containers()
	if err != nil {
		return source.Schema{}, err
	}
	sch := source.Schema{Kind: Kind, Format: "docker-json", FullyIndexed: true}
	values := map[string]map[string]bool{}
	unknown := map[string]bool{} // fields some container cannot list
	var from []coverage
	for _, c := range cs {
		d, err := c.src.Describe(ctx)
		if err != nil {
			return source.Schema{}, err
		}
		sch.Streams += d.Streams
		sch.Bytes += d.Bytes
		if !d.Oldest.IsZero() && (sch.Oldest.IsZero() || d.Oldest.Before(sch.Oldest)) {
			sch.Oldest = d.Oldest
		}
		if d.Newest.After(sch.Newest) {
			sch.Newest = d.Newest
		}
		sch.FullyIndexed = sch.FullyIndexed && d.FullyIndexed
		from = append(from, coverage{d.IndexedFrom, d.FullyIndexed})
		for _, f := range d.Fields {
			k := index.TermKey(f.Name, f.Label)
			if f.Values == nil {
				unknown[k] = true
				continue
			}
			if values[k] == nil {
				values[k] = map[string]bool{}
			}
			for _, v := range f.Values {
				values[k][v] = true
			}
		}
	}
	sch.IndexedFrom = mergeCoverage(from)
	names := make([]string, len(cs))
	for i, c := range cs {
		names[i] = c.c.Name
	}
	for _, f := range s.opts.Trusted {
		name, label := index.SplitKey(f)
		info := source.FieldInfo{Name: name, Label: label, Trusted: true}
		switch {
		case f == index.LabelKey(ContainerField):
			if len(names) <= index.MaxDistinct {
				info.Values = names
			}
		case !unknown[f] && len(values[f]) <= index.MaxDistinct:
			for v := range values[f] {
				info.Values = append(info.Values, v)
			}
			sort.Strings(info.Values)
		}
		sch.Fields = append(sch.Fields, info)
	}
	return sch, nil
}

type coverage struct {
	from time.Time
	full bool
}

// mergeCoverage: every record from the result on is indexed in every
// container. A container with nothing indexed and something left to index
// leaves none; one with nothing at all does not count.
func mergeCoverage(cs []coverage) time.Time {
	var out time.Time
	for _, c := range cs {
		if c.from.IsZero() {
			if c.full {
				continue
			}
			return time.Time{}
		}
		if c.from.After(out) {
			out = c.from
		}
	}
	return out
}

// IndexStep indexes the served containers in turn, within maxBytes (upkeep:
// see file.Source.IndexStep).
func (s *Source) IndexStep(ctx context.Context, maxBytes int64, upkeep bool) (int64, bool, error) {
	cs, err := s.containers()
	if err != nil {
		return 0, false, err
	}
	var done int64
	all := true
	for _, c := range cs {
		if done >= maxBytes {
			return done, false, nil
		}
		n, ok, err := c.src.IndexStep(ctx, maxBytes-done, upkeep)
		done += n
		if err != nil {
			return done, false, err
		}
		all = all && ok
	}
	return done, all, nil
}

// IndexCounts merges the served containers' index counts; a selector term
// on the container prunes whole containers first.
func (s *Source) IndexCounts(ctx context.Context, q source.CountQuery) (source.CountResult, error) {
	cs, err := s.containers()
	if err != nil {
		return source.CountResult{}, err
	}
	var res source.CountResult
	acc := map[string]*source.CountRow{}
	var from []coverage
	for _, c := range s.selected(cs, q.Selector) {
		r, err := c.src.IndexCounts(ctx, q)
		if err != nil {
			return source.CountResult{}, err
		}
		for _, row := range r.Rows {
			k := row.Bucket.String() + "|" + strconv.Itoa(len(row.Vals)) + "|" + strings.Join(quoteAll(row.Vals), "|")
			if acc[k] == nil {
				acc[k] = &source.CountRow{Bucket: row.Bucket, Vals: row.Vals}
			}
			acc[k].N += row.N
		}
		res.Untimed += r.Untimed
		res.Residual.Chunks = append(res.Residual.Chunks, s.wrapPlan(c, r.Residual)...)
		cov := coverage{from: r.IndexedFrom}
		if r.IndexedFrom.IsZero() {
			d, err := c.src.Describe(ctx)
			if err != nil {
				return source.CountResult{}, err
			}
			cov.full = d.FullyIndexed
		}
		from = append(from, cov)
	}
	for _, r := range acc {
		res.Rows = append(res.Rows, *r)
	}
	sort.Slice(res.Rows, func(i, j int) bool {
		if !res.Rows[i].Bucket.Equal(res.Rows[j].Bucket) {
			return res.Rows[i].Bucket.Before(res.Rows[j].Bucket)
		}
		return slices.Compare(res.Rows[i].Vals, res.Rows[j].Vals) < 0
	})
	res.IndexedFrom = mergeCoverage(from)
	return res, nil
}

func quoteAll(vs []string) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = strconv.Quote(v)
	}
	return out
}

var (
	_ source.Source  = (*Source)(nil)
	_ source.Counter = (*Source)(nil)
	_ index.Indexer  = (*Source)(nil)
)
