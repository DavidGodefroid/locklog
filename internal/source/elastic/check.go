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
	readCluster = []string{"monitor", "read_ilm", "read_slm", "read_pipeline", "read_ccr",
		// The monitor_* privileges of Elasticsearch 8, by name: a new
		// one is refused until listed.
		"monitor_connector", "monitor_data_frame_transforms", "monitor_enrich", "monitor_inference", "monitor_ml",
		"monitor_rollup", "monitor_snapshot", "monitor_text_structure", "monitor_transform", "monitor_watcher"}
	readIndex = []string{"read", "view_index_metadata", "monitor", "read_cross_cluster"}
	// readOnlyRoles are the OpenSearch built-in roles that grant no write
	// or manage permission.
	readOnlyRoles = []string{"readall", "readall_and_monitor"}
)

// readOnlyCluster reports a cluster privilege of the allowlist.
func readOnlyCluster(p string) bool { return slices.Contains(readCluster, p) }

// indexGrantKeys are the members of an index grant locklog knows: the
// document- and field-level restrictions only narrow it. Any other member
// is refused (fail closed).
var indexGrantKeys = []string{"names", "privileges", "field_security", "query", "allow_restricted_indices"}

// checkGrantShape refuses an index grant list that is not a JSON array of
// objects with known members (remote grants may also name clusters).
func checkGrantShape(raw json.RawMessage, remote bool) error {
	if raw == nil {
		return nil
	}
	var gs []map[string]json.RawMessage
	if !isArray(raw) || json.Unmarshal(raw, &gs) != nil {
		return errResponse
	}
	for _, g := range gs {
		if g == nil || !isArray(g["names"]) || !isArray(g["privileges"]) {
			return errResponse
		}
		for k := range g {
			if !slices.Contains(indexGrantKeys, k) && (!remote || k != "clusters") {
				return fmt.Errorf("elasticsearch source: an index grant holds an unknown member %q", k)
			}
		}
	}
	return nil
}

// isArray reports a JSON array (not null).
func isArray(raw json.RawMessage) bool {
	t := strings.TrimSpace(string(raw))
	return strings.HasPrefix(t, "[")
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
// allowlist, on any pattern (fail closed): any cluster privilege off the
// allowlist, global, application and run_as grants, any remote grant off
// the allowlist, and any index privilege off the allowlist, whatever index
// pattern, alias or data stream it names. Grants covering one of readable
// (the source's names and patterns and what they resolve to) are marked.
func esWrite(body []byte, readable []string) ([]string, error) {
	var raw map[string]json.RawMessage
	if json.Unmarshal(body, &raw) != nil || !isArray(raw["cluster"]) || !isArray(raw["indices"]) {
		return nil, errResponse
	}
	if err := checkGrantShape(raw["indices"], false); err != nil {
		return nil, err
	}
	if err := checkGrantShape(raw["remote_indices"], true); err != nil {
		return nil, err
	}
	if rc := raw["remote_cluster"]; rc != nil {
		var es []map[string]json.RawMessage
		if !isArray(rc) || json.Unmarshal(rc, &es) != nil {
			return nil, errResponse
		}
		for _, e := range es {
			if e == nil || !isArray(e["privileges"]) || !isArray(e["clusters"]) {
				return nil, errResponse
			}
			for k := range e {
				if k != "privileges" && k != "clusters" {
					return nil, fmt.Errorf("elasticsearch source: a remote_cluster grant holds an unknown member %q", k)
				}
			}
		}
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
	// Fail closed: a grant off the allowlist is refused on any pattern,
	// whether or not it covers what the source reads (a pattern, alias or
	// data stream can come to resolve to the source's indices later). A
	// grant that covers them now is marked so.
	for _, g := range u.Indices {
		mark := ""
		if covers(g.Names, readable) {
			mark = " (reaches the source's indices)"
		}
		for _, p := range g.Privileges {
			if !slices.Contains(readIndex, p) {
				write = append(write, strings.Join(g.Names, ",")+":"+p+mark)
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
// (_resolve/index: the key must be able to), then lists the key's grants
// beyond the read-only allowlist on any pattern (_privileges), marking
// those that reach the source's indices.
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
	if len(r.Roles) == 0 {
		// No role at all: the plugin's admin certificate (admin_dn) and
		// a superuser of another backend look like this. Fail closed.
		write = append(write, "no security role (an admin certificate or an unmapped user cannot be told apart)")
	}
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
//
// Re-Check policy expected from the wiring: on a production profile, no
// Plan, Scan, count or Describe before Check has succeeded (the source is
// not served otherwise); Check may run again at any time (on reconnect,
// on a timer): while it runs, and after it fails, the source pushes no
// trusted term and serves no count, and streams planned under an earlier
// state that pushed a term now kept local are stale (source.ErrStale).
func (s *Source) Check(ctx context.Context, production bool) (Info, error) {
	var info Info
	var err error
	// Until this Check completes, no trusted term is pushed and no count
	// is served on the server.
	s.mu.Lock()
	s.checked = false
	s.mu.Unlock()
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
	// The fields the source names in a body: the time field, the trusted
	// and tiebreaker fields, and the selector's (its terms are the scope:
	// on a text field a term matches a token, which widens it).
	keywords := slices.Clone(s.o.TrustedFields)
	if s.o.TieBreaker != "" {
		keywords = append(keywords, s.o.TieBreaker)
	}
	for k := range s.o.Selector {
		if !slices.Contains(keywords, k) {
			keywords = append(keywords, k)
		}
	}
	sort.Strings(keywords)
	fields := append([]string{s.o.TimeField}, keywords...)
	fc, err := s.fieldCaps(ctx, fields)
	if err != nil {
		return info, fmt.Errorf("elasticsearch source: %w", err)
	}
	for _, f := range fields {
		types, ok := fc.Fields[f]
		if !ok || len(types) == 0 {
			if production {
				return info, fmt.Errorf("elasticsearch source: no index of the source maps %s: a production profile refuses a field it cannot type-check", f)
			}
			continue // no index maps it yet
		}
		for t := range types {
			switch {
			case f == s.o.TimeField:
				if t != "date" && t != "date_nanos" {
					return info, fmt.Errorf("elasticsearch source: the time field %s is a %s, not a date", f, t)
				}
			case t != "keyword" && t != "constant_keyword":
				return info, fmt.Errorf("elasticsearch source: %s is a %s field; trusted, selector and tiebreaker fields must be keyword fields", f, t)
			}
		}
	}
	// Every keyword field the source names must be, in every index the
	// source reads, a concrete keyword or constant_keyword field (an
	// alias resolved to its target) without a normalizer (the indexed
	// term would differ from the value) or a script, that no copy_to
	// writes into and no runtime field (composite subfields included)
	// shadows: else refused. ignore_above (on the field, index-level, or
	// a non-standard index mode) leaves long values unindexed, null_value
	// indexes a value for an absent field: terms on such a field are kept
	// local (pushable), counts by it are not served; a selector field
	// with a null_value is refused (it would select absent ones). A
	// field missing from an index is refused on production; mappings or
	// settings that cannot be read are refused on production, and keep
	// every term local elsewhere.
	selector := func(f string) bool { _, ok := s.o.Selector[f]; return ok }
	related := func(a, b string) bool { return a == b || strings.HasPrefix(a, b+".") || strings.HasPrefix(b, a+".") }
	local := map[string]bool{}
	m, err := s.mappingFacts(ctx, info.Flavour)
	switch {
	case err != nil && production:
		return info, fmt.Errorf("elasticsearch source: reading the mappings and settings (the key needs view_index_metadata), which a production profile requires: %w", err)
	case err != nil:
		for _, f := range keywords {
			local[f] = true
		}
	default:
		for _, ix := range m.indices {
			if ix.dynamicRisk != "" {
				return info, fmt.Errorf("elasticsearch source: %s in some index: new fields could be copied into, or computed as, the source's fields; refused", ix.dynamicRisk)
			}
			// The time field too: neither copied into nor computed.
			_, tpath, _ := ix.field(s.o.TimeField)
			for _, r := range ix.runtime {
				if related(r, s.o.TimeField) || related(r, tpath) {
					return info, fmt.Errorf("elasticsearch source: the time field %s is (under) a runtime field in some index", s.o.TimeField)
				}
			}
			for _, t := range ix.copyTo {
				if related(t, s.o.TimeField) || related(t, tpath) {
					return info, fmt.Errorf("elasticsearch source: a copy_to writes into the time field %s in some index", s.o.TimeField)
				}
			}
		}
		for _, f := range keywords {
			for _, ix := range m.indices {
				d, path, ok := ix.field(f)
				for _, r := range ix.runtime {
					if f == r || strings.HasPrefix(f, r+".") || path == r || strings.HasPrefix(path, r+".") {
						return info, fmt.Errorf("elasticsearch source: %s is (under) a runtime field in some index: it cannot be trusted or selected on", f)
					}
				}
				for _, t := range ix.copyTo {
					if related(t, f) || (ok && related(t, path)) {
						return info, fmt.Errorf("elasticsearch source: a copy_to writes into %s in some index: its terms are not its documents' values; it cannot be trusted or selected on", f)
					}
				}
				switch {
				case !ok:
					if production {
						return info, fmt.Errorf("elasticsearch source: %s is not mapped in every index of the source: a production profile refuses it", f)
					}
					local[f] = true
					continue
				case d.Type != "keyword" && d.Type != "constant_keyword":
					return info, fmt.Errorf("elasticsearch source: %s is mapped as %q in some index; trusted, selector and tiebreaker fields must be keyword fields", f, d.Type)
				case d.Normalizer != "":
					return info, fmt.Errorf("elasticsearch source: %s has a normalizer in some index: its indexed terms are not its values; it cannot be trusted or selected on", f)
				case d.Script != nil:
					return info, fmt.Errorf("elasticsearch source: %s is computed by a script in some index: it cannot be trusted or selected on", f)
				case d.NullValue != nil && selector(f):
					return info, fmt.Errorf("elasticsearch source: selector field %s has a null_value in some index: the selector would match documents without it", f)
				}
				if d.IgnoreAbove != nil || d.NullValue != nil || ix.ignoreAbove {
					local[f] = true
				}
			}
		}
	}
	s.mu.Lock()
	s.local, s.checked = local, true
	s.mu.Unlock()
	return info, nil
}

// indexMapping is one index's fields by dotted name (multi-fields
// included), its runtime fields and whether index.mapping.ignore_above is
// set.
type indexMapping struct {
	fields map[string]mappingDef
	// runtime are the runtime field names (a composite's subfields
	// included), copyTo every copy_to target.
	runtime, copyTo []string
	ignoreAbove     bool
	// dynamicRisk names what lets new fields reach the source's ones:
	// a dynamic template with copy_to or a runtime mapping, or dynamic:
	// runtime at some level ("" when none).
	dynamicRisk string
}

// field returns the definition of f and its concrete path, an alias
// resolved to its target (Elasticsearch allows no alias of an alias). An
// alias whose target is not a mapped field returns the target's path and
// false.
func (ix indexMapping) field(f string) (mappingDef, string, bool) {
	d, ok := ix.fields[f]
	if ok && d.Type == "alias" {
		if d.Path == "" || d.Path == f {
			return mappingDef{}, "", false
		}
		p := d.Path
		d, ok = ix.fields[p]
		if !ok || d.Type == "alias" {
			return mappingDef{}, p, false // the target, for the runtime check
		}
		return d, p, true
	}
	return d, f, ok
}

// mappingFacts are the mappings of every index of the source.
type mappingFacts struct {
	indices map[string]indexMapping
}

// mappingFacts reads GET /{indices}/_mapping and GET /{indices}/_settings.
func (s *Source) mappingFacts(ctx context.Context, flavour string) (mappingFacts, error) {
	body, err := s.do(ctx, http.MethodGet, "/"+s.seg+"/_mapping", readParams(), nil)
	if err != nil {
		return mappingFacts{}, err
	}
	var idx map[string]struct {
		Mappings struct {
			Properties map[string]mappingDef `json:"properties"`
			Runtime    map[string]struct {
				Fields map[string]json.RawMessage `json:"fields"`
			} `json:"runtime"`
			Dynamic          json.RawMessage              `json:"dynamic"`
			DynamicTemplates []map[string]json.RawMessage `json:"dynamic_templates"`
		} `json:"mappings"`
	}
	if json.Unmarshal(body, &idx) != nil || idx == nil {
		return mappingFacts{}, errResponse
	}
	q := readParams()
	q.Set("flat_settings", "true")
	q.Set("include_defaults", "true")
	body, err = s.do(ctx, http.MethodGet, "/"+s.seg+"/_settings", q, nil)
	if err != nil {
		return mappingFacts{}, err
	}
	var settings map[string]struct {
		Settings map[string]json.RawMessage `json:"settings"`
		Defaults map[string]json.RawMessage `json:"defaults"`
	}
	if json.Unmarshal(body, &settings) != nil || settings == nil {
		return mappingFacts{}, errResponse
	}
	m := mappingFacts{indices: map[string]indexMapping{}}
	for name, i := range idx {
		ix := indexMapping{fields: map[string]mappingDef{}}
		var bad error
		var walk func(prefix string, props map[string]mappingDef)
		walk = func(prefix string, props map[string]mappingDef) {
			for n, d := range props {
				full := prefix + n
				ix.fields[full] = d
				if dynamicRisky(d.Dynamic) {
					ix.dynamicRisk = "dynamic: " + string(d.Dynamic) + " on " + full
				}
				if d.CopyTo != nil {
					ts, ok := stringOrArray(d.CopyTo)
					if !ok {
						bad = errResponse
					}
					ix.copyTo = append(ix.copyTo, ts...)
				}
				walk(full+".", d.Properties)
				walk(full+".", d.Fields)
			}
		}
		walk("", i.Mappings.Properties)
		if bad != nil {
			return mappingFacts{}, bad
		}
		if dynamicRisky(i.Mappings.Dynamic) {
			ix.dynamicRisk = "dynamic: " + string(i.Mappings.Dynamic)
		}
		for _, tmpl := range i.Mappings.DynamicTemplates {
			if len(tmpl) != 1 {
				return mappingFacts{}, errResponse
			}
			for name, raw := range tmpl {
				risk, err := templateRisk(raw)
				if err != nil {
					return mappingFacts{}, err
				}
				if risk != "" {
					ix.dynamicRisk = "the dynamic template " + strconv.Quote(name) + " " + risk
				}
			}
		}
		for n, r := range i.Mappings.Runtime {
			ix.runtime = append(ix.runtime, n)
			for sub := range r.Fields {
				ix.runtime = append(ix.runtime, n+"."+sub)
			}
		}
		st, ok := settings[name]
		if !ok {
			return mappingFacts{}, errResponse // every index's settings are read
		}
		ix.ignoreAbove = indexIgnoresAbove(st.Settings, st.Defaults, flavour)
		m.indices[name] = ix
	}
	return m, nil
}

// dynamicRisky reports a "dynamic" mapping parameter other than a boolean
// or one of "true", "false", "strict" (any case): "runtime" (new fields
// become runtime fields), and anything not understood.
func dynamicRisky(raw json.RawMessage) bool {
	if raw == nil {
		return false
	}
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return false
	}
	var v string
	if json.Unmarshal(raw, &v) != nil {
		return true
	}
	for _, ok := range []string{"true", "false", "strict"} {
		if strings.EqualFold(v, ok) {
			return false
		}
	}
	return true
}

// templateRisk judges one dynamic template. It is accepted (provably
// harmless) only when its mapping, walked at every depth (properties and
// fields included), has no copy_to, no script, no runtime type and no
// dynamic parameter other than a boolean, "true", "false" or "strict",
// and the template has no runtime member: then the fields it creates are
// ordinary indexed fields, which Check judges like any other where the
// source names them. An answer that does not decode is an error (refused
// on production).
func templateRisk(raw json.RawMessage) (string, error) {
	var t struct {
		Mapping *mappingDef     `json:"mapping"`
		Runtime json.RawMessage `json:"runtime"`
	}
	if err := json.Unmarshal(raw, &t); err != nil {
		return "", errResponse
	}
	if t.Runtime != nil {
		return "maps new fields as runtime fields", nil
	}
	if t.Mapping == nil {
		return "", nil
	}
	var walk func(d mappingDef, at string) string
	walk = func(d mappingDef, at string) string {
		switch {
		case strings.EqualFold(d.Type, "runtime"):
			return "maps new fields as runtime fields" + at
		case d.CopyTo != nil:
			return "has a copy_to" + at
		case d.Script != nil:
			return "has a script" + at
		case dynamicRisky(d.Dynamic):
			return "sets dynamic: " + string(d.Dynamic) + at
		}
		for _, sub := range []map[string]mappingDef{d.Properties, d.Fields} {
			for n, c := range sub {
				if r := walk(c, at+" under "+n); r != "" {
					return r
				}
			}
		}
		return ""
	}
	return walk(*t.Mapping, ""), nil
}

// stringOrArray decodes a string or an array of strings.
func stringOrArray(raw json.RawMessage) ([]string, bool) {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}, true
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		return many, true
	}
	return nil, false
}

// noLimit is the default of index.mapping.ignore_above on a standard
// index: no value is ignored.
const noLimit = "2147483647"

// indexIgnoresAbove reports whether an index may leave long keyword values
// unindexed whatever the field's mapping says: index.mapping.ignore_above
// set or defaulted below noLimit, or an index mode other than standard
// (logsdb and time_series default ignore_above; an unknown mode is assumed
// to). Elasticsearch reports index.mode among the defaults: absent there,
// it is not known to be standard (fail closed). OpenSearch 2.x has no index
// modes: absent, the index is standard.
func indexIgnoresAbove(settings, defaults map[string]json.RawMessage, flavour string) bool {
	// Flat settings hold strings and arrays: an object (nested settings)
	// is an answer not understood, so unknown.
	for _, m := range []map[string]json.RawMessage{settings, defaults} {
		for _, raw := range m {
			if strings.HasPrefix(strings.TrimSpace(string(raw)), "{") {
				return true
			}
		}
	}
	get := func(k string) (string, bool) {
		for _, m := range []map[string]json.RawMessage{settings, defaults} {
			if raw, ok := m[k]; ok {
				var v string
				if json.Unmarshal(raw, &v) != nil {
					return "?", true // not a string: unknown
				}
				return v, true
			}
		}
		return "", false
	}
	if v, ok := get("index.mapping.ignore_above"); ok && v != noLimit {
		return true
	}
	switch mode, ok := get("index.mode"); {
	case ok:
		return mode != "standard"
	default:
		return flavour != FlavourOpenSearch
	}
}

// mappingDef is one field of a mapping, as far as Check reads it.
type mappingDef struct {
	Type        string                `json:"type"`
	Path        string                `json:"path"`
	Normalizer  string                `json:"normalizer"`
	Script      json.RawMessage       `json:"script"`
	NullValue   json.RawMessage       `json:"null_value"`
	CopyTo      json.RawMessage       `json:"copy_to"`
	Dynamic     json.RawMessage       `json:"dynamic"`
	IgnoreAbove *json.Number          `json:"ignore_above"`
	Properties  map[string]mappingDef `json:"properties"`
	Fields      map[string]mappingDef `json:"fields"`
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
			if json.Unmarshal(top[termsName(i)], &a) != nil || a.SumOtherDocCnt > 0 || a.DocCountError != 0 {
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
	_ source.Source   = (*Source)(nil)
	_ source.Counter  = (*Source)(nil)
	_ source.Splitter = (*Source)(nil)
)
