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
	for _, g := range s.List {
		for _, m := range g.Minutes {
			for _, c := range m.Counts {
				if len(c.Vals) != len(s.Fields) {
					return nil, errors.New("index tuple width")
				}
			}
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
	st.mu.Lock()
	defer st.mu.Unlock()
	k := key(source, dev, ino)
	delete(st.streams, k)
	st.dirty[k] = source
}

// Flush writes the changed stream indexes atomically (0600).
func (st *Store) Flush() error {
	st.mu.Lock()
	defer st.mu.Unlock()
	for k, source := range st.dirty {
		dir := filepath.Join(st.dir, source)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		p := filepath.Join(dir, filepath.Base(k)+".json.gz")
		s := st.streams[k]
		if s == nil {
			if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			delete(st.dirty, k)
			continue
		}
		if err := write(p, s); err != nil {
			return err
		}
		delete(st.dirty, k)
	}
	return nil
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
