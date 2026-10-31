package index

import (
	"cmp"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"sync"
)

// granuleSize is the plan granule size (source.GranuleBytes; the index
// package does not import source).
const granuleSize = 1 << 20

// Stream is the index of one file stream.
type Stream struct {
	Version int `json:"version"`
	// Dev, Ino, Gen identify the stream; PrefixLen/PrefixHash are the
	// latest hashed prefix (a stream whose prefix no longer hashes the
	// same is another stream).
	Dev        uint64 `json:"dev"`
	Ino        uint64 `json:"ino"`
	Gen        string `json:"gen"`
	PrefixLen  int    `json:"prefix_len"`
	PrefixHash string `json:"prefix_hash"`
	// Compression of the file ("", "gzip", "zstd"). Size is the length
	// of the decompressed stream once a full pass measured it, else -1.
	Compression string `json:"compression,omitempty"`
	Size        int64  `json:"size"`
	// FileSize is a compressed file's own size when it was measured.
	FileSize int64 `json:"file_size,omitempty"`
	// Fields are the indexed fields, in tuple order; Dropped those
	// dropped for cardinality.
	Fields  []string `json:"fields"`
	Dropped []string `json:"dropped,omitempty"`
	// Granules, by granule number.
	Granules map[int64]*Granule `json:"-"`
	List     []*Granule         `json:"granules"`

	distinct []map[string]bool // per field, built on first Put
}

// NewStream returns an empty stream index for the given fields.
func NewStream(dev, ino uint64, gen string, fields []string) *Stream {
	return &Stream{Version: Version, Dev: dev, Ino: ino, Gen: gen, Size: -1,
		Fields: slices.Clone(fields), Granules: map[int64]*Granule{}}
}

// Put stores a granule, replacing an earlier one of the same number, and
// drops fields that exceed MaxDistinct values across the stream.
func (s *Stream) Put(g Granule) {
	gg := g
	s.Granules[g.N] = &gg
	if s.distinct == nil {
		s.distinct = make([]map[string]bool, len(s.Fields))
		for i := range s.distinct {
			s.distinct[i] = map[string]bool{}
		}
		for _, g := range s.Granules {
			s.note(g)
		}
	} else {
		s.note(&gg)
	}
	for {
		f := slices.IndexFunc(s.distinct, func(m map[string]bool) bool { return len(m) > MaxDistinct })
		if f < 0 {
			return
		}
		s.drop(f)
		s.distinct = slices.Delete(s.distinct, f, f+1)
	}
}

// PutBuilt stores a granule built over fields (the source's trusted fields,
// a superset of s.Fields once fields were dropped): its tuples are first
// projected onto s.Fields, merging tuples that become equal.
func (s *Stream) PutBuilt(g Granule, fields []string) {
	if !slices.Equal(fields, s.Fields) {
		pos := make([]int, len(s.Fields))
		for i, f := range s.Fields {
			pos[i] = slices.Index(fields, f)
		}
		project := func(cs []Count) []Count {
			m := map[string]*Count{}
			for _, c := range cs {
				vals := make([]string, len(pos))
				for i, p := range pos {
					if p >= 0 {
						vals[i] = c.Vals[p]
					}
				}
				k := tupleKey(vals)
				if m[k] == nil {
					m[k] = &Count{Vals: vals}
				}
				m[k].N += c.N
			}
			return sortedCounts(m)
		}
		ms := make([]Minute, len(g.Minutes))
		for j, m := range g.Minutes {
			ms[j] = Minute{M: m.M, Counts: project(m.Counts)}
		}
		g.Minutes, g.Untimed = ms, project(g.Untimed)
	}
	s.Put(g)
}

// note adds g's values to the distinct sets.
func (s *Stream) note(g *Granule) {
	each(g, func(vals []string) {
		for i, v := range vals {
			if v != Absent && v != Redacted && v != Other {
				s.distinct[i][v] = true
			}
		}
	})
}

func each(g *Granule, fn func([]string)) {
	for _, m := range g.Minutes {
		for _, c := range m.Counts {
			fn(c.Vals)
		}
	}
	for _, c := range g.Untimed {
		fn(c.Vals)
	}
}

// drop removes field i from every tuple, merging tuples that become equal.
func (s *Stream) drop(i int) {
	s.Dropped = append(s.Dropped, s.Fields[i])
	s.Fields = slices.Delete(slices.Clone(s.Fields), i, i+1)
	project := func(cs []Count) []Count {
		m := map[string]*Count{}
		for _, c := range cs {
			vals := slices.Delete(slices.Clone(c.Vals), i, i+1)
			k := tupleKey(vals)
			if m[k] == nil {
				m[k] = &Count{Vals: vals}
			}
			m[k].N += c.N
		}
		return sortedCounts(m)
	}
	// Stored granules are immutable (readers hold them outside the lock):
	// projected granules are new values.
	for n, g := range s.Granules {
		ng := *g
		ng.Minutes = make([]Minute, len(g.Minutes))
		for j, m := range g.Minutes {
			ng.Minutes[j] = Minute{M: m.M, Counts: project(m.Counts)}
		}
		ng.Untimed = project(g.Untimed)
		s.Granules[n] = &ng
	}
}

// Store keeps the stream indexes of every source in a directory.
type Store struct {
	dir     string
	mu      sync.Mutex
	streams map[string]*Stream // by key(source, dev, ino)
	dirty   map[string]string  // key -> source
	wmu     sync.Mutex         // serialises writers of Flush
}

var sourceRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,47}$`)

// Open opens (creating it 0700) the index directory and loads it. Files of
// another version, or unreadable ones, are ignored (and rebuilt).
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("index directory %s is accessible to others (mode %v); want 0700", dir, fi.Mode().Perm())
	}
	st := &Store{dir: dir, streams: map[string]*Stream{}, dirty: map[string]string{}}
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(p) != ".gz" {
			return err
		}
		source := filepath.Base(filepath.Dir(p))
		if !sourceRe.MatchString(source) {
			return nil
		}
		s, err := load(p)
		if err != nil {
			return nil // rebuilt
		}
		st.streams[key(source, s.Dev, s.Ino)] = s
		return nil
	})
	return st, err
}

func key(source string, dev, ino uint64) string {
	return source + "/" + strconv.FormatUint(dev, 16) + "-" + strconv.FormatUint(ino, 16)
}

func load(p string) (*Stream, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	var s Stream
	if err := json.NewDecoder(zr).Decode(&s); err != nil {
		return nil, err
	}
	if s.Version != Version {
		return nil, errors.New("index version")
	}
	s.Granules = map[int64]*Granule{}
	width := func(cs []Count) error {
		for _, c := range cs {
			if len(c.Vals) != len(s.Fields) || c.N < 0 {
				return errors.New("index tuple width")
			}
		}
		return nil
	}
	for _, g := range s.List {
		if g == nil || g.N < 0 || g.Start < 0 || g.End < g.Start || g.Start/granuleSize != g.N {
			return nil, errors.New("index granule")
		}
		for _, m := range g.Minutes {
			if err := width(m.Counts); err != nil {
				return nil, err
			}
		}
		if err := width(g.Untimed); err != nil {
			return nil, err
		}
		s.Granules[g.N] = g
	}
	s.List = nil
	return &s, nil
}

// With calls fn with the index of the stream (nil when none), under the
// store's lock. fn may modify the stream or return a new one to store
// (replace); returning a non-nil stream marks it dirty.
func (st *Store) With(source string, dev, ino uint64, fn func(*Stream) *Stream) {
	if !sourceRe.MatchString(source) {
		panic("index: invalid source name") // validated by the config
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	k := key(source, dev, ino)
	if s := fn(st.streams[k]); s != nil {
		st.streams[k] = s
		st.dirty[k] = source
	}
}

// Delete forgets a stream's index (its file is removed at the next Flush).
func (st *Store) Delete(source string, dev, ino uint64) {
	if !sourceRe.MatchString(source) {
		panic("index: invalid source name")
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	k := key(source, dev, ino)
	delete(st.streams, k)
	st.dirty[k] = source
}

// Flush writes the changed stream indexes atomically (0600). The streams
// are copied under the lock and written outside it, so queries are not held
// up by disk writes.
func (st *Store) Flush() error {
	type job struct {
		key, source string
		s           *Stream
	}
	st.wmu.Lock() // before the snapshot: flushes land in order
	defer st.wmu.Unlock()
	st.mu.Lock()
	var jobs []job
	for k, source := range st.dirty {
		var cp *Stream
		if s := st.streams[k]; s != nil {
			c := *s
			c.Granules = make(map[int64]*Granule, len(s.Granules))
			for n, g := range s.Granules {
				c.Granules[n] = g // immutable once stored
			}
			c.Fields, c.Dropped = slices.Clone(s.Fields), slices.Clone(s.Dropped)
			cp = &c
		}
		jobs = append(jobs, job{k, source, cp})
		delete(st.dirty, k)
	}
	st.mu.Unlock()
	var firstErr error
	for _, j := range jobs {
		dir := filepath.Join(st.dir, j.source)
		p := filepath.Join(dir, filepath.Base(j.key)+".json.gz")
		var err error
		if err = os.MkdirAll(dir, 0o700); err == nil {
			if j.s == nil {
				if err = os.Remove(p); errors.Is(err, fs.ErrNotExist) {
					err = nil
				}
			} else {
				err = write(p, j.s)
			}
		}
		if err != nil {
			// Written again at the next flush.
			st.mu.Lock()
			if _, again := st.dirty[j.key]; !again {
				st.dirty[j.key] = j.source
			}
			st.mu.Unlock()
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

func write(p string, s *Stream) error {
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	out := *s
	out.List = make([]*Granule, 0, len(s.Granules))
	for _, g := range s.Granules {
		out.List = append(out.List, g)
	}
	slices.SortFunc(out.List, func(a, b *Granule) int { return cmp.Compare(a.N, b.N) })
	zw := gzip.NewWriter(tmp)
	if err := json.NewEncoder(zw).Encode(&out); err != nil {
		tmp.Close()
		return err
	}
	if err := zw.Close(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p)
}

// Dir returns the store's directory.
func (st *Store) Dir() string { return st.dir }
