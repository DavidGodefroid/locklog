package elastic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/DavidGodefroid/locklog/internal/egress"
	"github.com/DavidGodefroid/locklog/internal/source"
)

// Info is what Check learnt of the backend.
type Info struct {
	Flavour string
	Version string
	// Write lists the write or manage privileges the credentials hold
	// (Elasticsearch), or the roles not known to be read-only
	// (OpenSearch). Empty on a read-only key.
	Write []string
	// Verified is set when the privileges could be read.
	Verified bool
}

type rootResponse struct {
	Version struct {
		Number       string `json:"number"`
		Distribution string `json:"distribution"`
		BuildFlavor  string `json:"build_flavor"`
	} `json:"version"`
}

// detect reads GET / and returns the flavour and version.
func (s *Source) detect(ctx context.Context) (string, string, error) {
	body, err := s.do(ctx, http.MethodGet, "/", nil, nil)
	if err != nil {
		return "", "", fmt.Errorf("elasticsearch source: reading the backend version (the key needs the read-only monitor privilege): %w", err)
	}
	var r rootResponse
	if json.Unmarshal(body, &r) != nil || r.Version.Number == "" {
		return "", "", errResponse
	}
	major, err := strconv.Atoi(strings.SplitN(r.Version.Number, ".", 2)[0])
	if err != nil {
		return "", "", errResponse
	}
	switch {
	case r.Version.Distribution == "opensearch":
		if major < 2 {
			return "", "", fmt.Errorf("elasticsearch source: OpenSearch %s is not supported (2.x and later)", r.Version.Number)
		}
		return FlavourOpenSearch, r.Version.Number, nil
	case r.Version.Distribution == "":
		if major < 8 {
			return "", "", fmt.Errorf("elasticsearch source: Elasticsearch %s is not supported (8.x and later)", r.Version.Number)
		}
		return FlavourElasticsearch, r.Version.Number, nil
	}
	return "", "", errors.New("elasticsearch source: unknown backend distribution")
}

// The privileges a read-only key may hold: everything else makes it more
// than a reader (an allowlist: a privilege Elasticsearch adds later is
// refused until listed here).
var (
	readCluster = []string{"monitor", "read_ilm", "read_slm", "read_pipeline", "read_ccr"}
	readIndex   = []string{"read", "view_index_metadata", "monitor", "read_cross_cluster"}
	// readOnlyRoles are the OpenSearch built-in roles that grant no write
	// or manage permission.
	readOnlyRoles = []string{"readall", "readall_and_monitor"}
)

// readOnlyCluster reports a cluster privilege of the allowlist. The
// monitor_* privileges (monitor_ml, monitor_watcher, ...) read only.
func readOnlyCluster(p string) bool {
	return slices.Contains(readCluster, p) || strings.HasPrefix(p, "monitor_")
}

// indexGrant is one index grant of a _privileges answer.
type indexGrant struct {
	Names      []string `json:"names"`
	Privileges []string `json:"privileges"`
}

// userPrivileges is GET /_security/user/_privileges: every grant of the
// user, on every pattern.
type userPrivileges struct {
	Cluster      []string          `json:"cluster"`
	Global       []json.RawMessage `json:"global"`
	Indices      []indexGrant      `json:"indices"`
	Applications []json.RawMessage `json:"applications"`
	RunAs        []string          `json:"run_as"`
	// Remote grants (cross-cluster): judged as local ones, on any index.
	RemoteIndices []indexGrant `json:"remote_indices"`
	RemoteCluster []struct {
		Privileges []string `json:"privileges"`
	} `json:"remote_cluster"`
}

// knownPrivilegeKeys are the members of a _privileges answer locklog
// judges; any other non-empty member is refused (fail closed).
var knownPrivilegeKeys = []string{"cluster", "global", "indices", "applications", "run_as", "remote_indices", "remote_cluster"}

// resolveResponse is GET /_resolve/index/{indices}: the indices, aliases
// and data streams the source's names and patterns cover, as the key sees
// them (the read privilege includes resolving).
type resolveResponse struct {
	Indices []struct {
		Name       string   `json:"name"`
		Aliases    []string `json:"aliases"`
		DataStream string   `json:"data_stream"`
	} `json:"indices"`
	Aliases []struct {
		Name    string   `json:"name"`
		Indices []string `json:"indices"`
	} `json:"aliases"`
	DataStreams []struct {
		Name           string   `json:"name"`
		BackingIndices []string `json:"backing_indices"`
	} `json:"data_streams"`
}

// readable returns every name the source reads through: its configured
// names and patterns, and the indices, aliases, data streams and backing
// indices they resolve to.
func (s *Source) readable(ctx context.Context) ([]string, error) {
	body, err := s.do(ctx, http.MethodGet, "/_resolve/index/"+s.seg, readParams(), nil)
	if err != nil {
		return nil, err
	}
	var r resolveResponse
	var raw map[string]json.RawMessage
	if json.Unmarshal(body, &r) != nil || json.Unmarshal(body, &raw) != nil || raw["indices"] == nil {
		return nil, errResponse
	}
	names := strings.Split(s.seg, ",")
	for _, i := range r.Indices {
		names = append(names, i.Name, i.DataStream)
		names = append(names, i.Aliases...)
	}
	for _, a := range r.Aliases {
		names = append(names, a.Name)
		names = append(names, a.Indices...)
	}
	for _, d := range r.DataStreams {
		names = append(names, d.Name)
		names = append(names, d.BackingIndices...)
	}
	names = slices.DeleteFunc(names, func(n string) bool { return n == "" })
	sort.Strings(names)
	return slices.Compact(names), nil
}

// globMatches reports whether the role index pattern g ('*' any run, '?'
// one character) matches name n, or, for a trailing-'*' pattern n of the
// source, whether g matches some name n covers. A pattern locklog cannot
// read exactly (a /regex/, date math, a remote cluster) covers everything:
// a grant through it is judged on every index.
func globMatches(g, n string) bool {
	if g == "" || strings.ContainsAny(g, "/<>{}:\\[") {
		return true
	}
	if g[0] == '-' {
		return true // an exclusion: judged as covering, fail closed
	}
	prefix, open := strings.CutSuffix(n, "*")
	// An automaton over the name: the states are positions in g.
	states := closure(g, map[int]bool{0: true})
	for i := 0; i < len(prefix) && len(states) > 0; i++ {
		next := map[int]bool{}
		for st := range states {
			if st >= len(g) {
				continue
			}
			switch g[st] {
			case '*':
				next[st] = true
			case '?':
				next[st+1] = true
			default:
				if g[st] == prefix[i] {
					next[st+1] = true
				}
			}
		}
		states = closure(g, next)
	}
	if open {
		// Any suffix may follow: some name n covers is matched once a
		// state survives the prefix.
		return len(states) > 0
	}
	return states[len(g)]
}

// closure adds, for every state on a '*', the state after it.
func closure(g string, states map[int]bool) map[int]bool {
	for changed := true; changed; {
		changed = false
		for st := range states {
			if st < len(g) && g[st] == '*' && !states[st+1] {
				states[st+1] = true
				changed = true
			}
		}
	}
	return states
}

// covers reports whether a grant on names reaches any name the source
// reads.
func covers(names, readable []string) bool {
	for _, g := range names {
		for _, n := range readable {
			if globMatches(g, n) {
				return true
			}
		}
	}
	return false
}

// esWrite lists every grant of a _privileges answer beyond the read-only
// allowlist that reaches what the source reads: any cluster privilege off
// the allowlist, global, application and run_as grants, any remote grant
// off the allowlist, and an index privilege off the allowlist on a pattern
// covering one of readable (the source's names and patterns and what they
// resolve to).
func esWrite(body []byte, readable []string) ([]string, error) {
	var raw map[string]json.RawMessage
	if json.Unmarshal(body, &raw) != nil || raw["cluster"] == nil || raw["indices"] == nil {
		return nil, errResponse
	}
	var write []string
	for k, v := range raw {
		if !slices.Contains(knownPrivilegeKeys, k) {
			if t := strings.TrimSpace(string(v)); t != "[]" && t != "{}" && t != "null" {
				write = append(write, "unknown:"+k)
			}
		}
	}
	var u userPrivileges
	if json.Unmarshal(body, &u) != nil {
		return nil, errResponse
	}
	for _, p := range u.Cluster {
		if !readOnlyCluster(p) {
			write = append(write, "cluster:"+p)
		}
	}
	for _, rc := range u.RemoteCluster {
		for _, p := range rc.Privileges {
			if !readOnlyCluster(p) {
				write = append(write, "remote_cluster:"+p)
			}
		}
	}
	for _, g := range u.RemoteIndices {
		for _, p := range g.Privileges {
			if !slices.Contains(readIndex, p) {
				write = append(write, "remote:"+strings.Join(g.Names, ",")+":"+p)
			}
		}
	}
	for _, g := range u.Indices {
		if !covers(g.Names, readable) {
			continue
		}
		for _, p := range g.Privileges {
			if !slices.Contains(readIndex, p) {
				write = append(write, strings.Join(g.Names, ",")+":"+p)
			}
		}
	}
	if len(u.Global) > 0 {
		write = append(write, "global privileges")
	}
	if len(u.Applications) > 0 {
		write = append(write, "application privileges")
	}
	if len(u.RunAs) > 0 {
		write = append(write, "run_as:"+strings.Join(u.RunAs, ","))
	}
	sort.Strings(write)
	return slices.Compact(write), nil
}

// esPrivileges resolves what the source's names and patterns cover
// (_resolve/index), then lists the key's grants beyond the read-only
// allowlist on any of it (_privileges): a write grant on a concrete index
// a read-only pattern matches, or on a pattern covering one, is listed.
func (s *Source) esPrivileges(ctx context.Context) ([]string, error) {
	readable, err := s.readable(ctx)
	if err != nil {
		return nil, err
	}
	body, err := s.do(ctx, http.MethodGet, egress.ElasticUserPrivilegesPath, nil, nil)
	if err != nil {
		return nil, err
	}
	return esWrite(body, readable)
}

type authInfoResponse struct {
	Roles []string `json:"roles"`
}

// osPrivileges lists the OpenSearch security roles of the key that are not
// known read-only: the built-in readall roles, and the ones the human
// vouches for (ReadOnlyRoles). A role's permissions are not readable with
// a read-only key, so any other role is refused, whatever it grants.
func (s *Source) osPrivileges(ctx context.Context) ([]string, error) {
	body, err := s.do(ctx, http.MethodGet, egress.OpenSearchAuthInfoPath, nil, nil)
	if err != nil {
		return nil, err
	}
	var r authInfoResponse
	if json.Unmarshal(body, &r) != nil || r.Roles == nil {
		return nil, errResponse
	}
	var write []string
	for _, role := range r.Roles {
		if !slices.Contains(readOnlyRoles, role) && !slices.Contains(s.o.ReadOnlyRoles, role) {
			write = append(write, "role:"+role)
		}
	}
	sort.Strings(write)
	return write, nil
}

type fieldCapsResponse struct {
	Indices []string                                  `json:"indices"`
	Fields  map[string]map[string]fieldCapsTypeAnswer `json:"fields"`
}

type fieldCapsTypeAnswer struct {
	Type         string `json:"type"`
	Aggregatable bool   `json:"aggregatable"`
}

func (s *Source) fieldCaps(ctx context.Context, fields []string) (fieldCapsResponse, error) {
	q := readParams()
	q.Set("fields", strings.Join(fields, ","))
	body, err := s.do(ctx, http.MethodGet, "/"+s.seg+"/_field_caps", q, nil)
	if err != nil {
		return fieldCapsResponse{}, err
	}
	var r fieldCapsResponse
	if json.Unmarshal(body, &r) != nil || r.Fields == nil {
		return fieldCapsResponse{}, errResponse
	}
	return r, nil
}

// Check reads the backend's flavour and version, the credentials'
// privileges and the trusted fields' types. A production profile refuses a
// key with any write or manage privilege, or one whose privileges cannot
// be read (security disabled, an unknown OpenSearch role). Trusted fields
// must be keyword fields; the time field a date.
func (s *Source) Check(ctx context.Context, production bool) (Info, error) {
	var info Info
	var err error
	if info.Flavour, info.Version, err = s.detect(ctx); err != nil {
		return info, err
	}
	if want := map[string]string{KindElastic: FlavourElasticsearch, KindOpenSearch: FlavourOpenSearch}[s.o.Kind]; info.Flavour != want {
		return info, fmt.Errorf("elasticsearch source: the backend is %s, the source is kind = %q", info.Flavour, s.o.Kind)
	}
	var write []string
	if info.Flavour == FlavourOpenSearch {
		write, err = s.osPrivileges(ctx)
	} else {
		write, err = s.esPrivileges(ctx)
	}
	switch {
	case err == nil:
		info.Verified, info.Write = true, write
	case production:
		return info, fmt.Errorf("elasticsearch source: the key's privileges cannot be read, which a production profile refuses: %w", err)
	}
	if production && len(info.Write) > 0 {
		return info, fmt.Errorf("elasticsearch source: the key holds write or manage privileges (%s): a production profile needs a read-only key", strings.Join(info.Write, ", "))
	}
	fields := append([]string{s.o.TimeField}, s.o.TrustedFields...)
	if s.o.TieBreaker != "" {
		fields = append(fields, s.o.TieBreaker)
	}
	fc, err := s.fieldCaps(ctx, fields)
	if err != nil {
		return info, fmt.Errorf("elasticsearch source: %w", err)
	}
	for _, f := range fields {
		types, ok := fc.Fields[f]
		if !ok {
			continue // no index maps it yet
		}
		for t := range types {
			switch {
			case f == s.o.TimeField:
				if t != "date" && t != "date_nanos" {
					return info, fmt.Errorf("elasticsearch source: the time field %s is a %s, not a date", f, t)
				}
			case t != "keyword" && t != "constant_keyword":
				return info, fmt.Errorf("elasticsearch source: %s is a %s field; trusted and tiebreaker fields must be keyword fields", f, t)
			}
		}
	}
	return info, nil
}

// MaxDescribeValues is the most values Describe lists of a trusted field.
const MaxDescribeValues = 64

// Describe lists the fields of the source's indices (names: masked by the
// caller), marks the trusted ones, and lists the trusted fields' values
// of the last 24 hours when they are few.
func (s *Source) Describe(ctx context.Context) (source.Schema, error) {
	sch := source.Schema{Kind: s.o.Kind, Format: s.o.Parser.Options().Format}
	fc, err := s.fieldCaps(ctx, []string{"*"})
	if err != nil {
		return sch, fmt.Errorf("elasticsearch source: %w", err)
	}
	sch.Streams = len(fc.Indices)
	names := make([]string, 0, len(fc.Fields))
	for n := range fc.Fields {
		if strings.HasPrefix(n, "_") || checkField(n) != nil {
			continue // metadata fields, names locklog cannot name
		}
		names = append(names, n)
	}
	for _, t := range s.o.TrustedFields {
		if !slices.Contains(names, t) {
			names = append(names, t)
		}
	}
	sort.Strings(names)
	values := map[string][]string{}
	if len(s.o.TrustedFields) > 0 {
		end := s.o.Now().Truncate(time.Millisecond)
		qry, err := s.filter(source.Selector{}).query(s.o.TimeField, end.Add(-24*time.Hour), end)
		if err != nil {
			return sch, fmt.Errorf("elasticsearch source: %w", err)
		}
		aggs := map[string]Agg{}
		for i, f := range s.o.TrustedFields {
			aggs[termsName(i)] = Agg{Terms: &TermsAgg{Field: f, Size: MaxDescribeValues}}
		}
		body, err := searchJSON(SearchBody{Size: 0, Timeout: SearchTimeout, Query: qry, Aggs: aggs})
		if err != nil {
			return sch, err
		}
		resp, err := s.do(ctx, http.MethodPost, s.searchPath(), readParams(), body)
		if err != nil {
			return sch, fmt.Errorf("elasticsearch source: %w", err)
		}
		var sr searchResponse
		var top map[string]json.RawMessage
		if json.Unmarshal(resp, &sr) != nil || json.Unmarshal(sr.Aggregations, &top) != nil {
			return sch, errResponse
		}
		for i, f := range s.o.TrustedFields {
			var a aggJSON
			if json.Unmarshal(top[termsName(i)], &a) != nil || a.SumOtherDocCnt > 0 {
				continue
			}
			var vs []string
			for _, b := range a.Buckets {
				if v, ok := stringValues(json.RawMessage("[" + string(b.Key) + "]")); ok && len(v) == 1 {
					vs = append(vs, v[0])
				}
			}
			sort.Strings(vs)
			values[f] = vs
		}
	}
	for _, n := range names {
		info := source.FieldInfo{Name: n, Label: true, Trusted: s.trusted(n)}
		if info.Trusted {
			info.Values = values[n]
		}
		sch.Fields = append(sch.Fields, info)
	}
	return sch, nil
}

// The source is a source and answers counts on the server.
var (
	_ source.Source  = (*Source)(nil)
	_ source.Counter = (*Source)(nil)
)
