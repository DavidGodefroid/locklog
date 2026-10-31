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

// Privileges whose grant makes a key more than a reader. Elasticsearch
// refuses names it does not know, so the lists hold 8.x names only.
var (
	writeCluster = []string{"all", "manage", "manage_security", "manage_api_key", "manage_own_api_key", "manage_index_templates",
		"manage_ilm", "manage_pipeline", "manage_ingest_pipelines", "manage_slm", "manage_transform", "manage_ml", "manage_watcher",
		"manage_ccr", "manage_enrich", "manage_rollup", "manage_token"}
	writeIndex = []string{"all", "write", "index", "create", "create_doc", "delete", "delete_index", "create_index", "manage",
		"manage_ilm", "manage_follow_index", "maintenance", "auto_configure"}
	// readOnlyRoles are the OpenSearch built-in roles that grant no write
	// or manage permission.
	readOnlyRoles = []string{"readall", "readall_and_monitor"}
)

var errCannotRead = errors.New("elasticsearch source: the key cannot read")

type hasPrivilegesResponse struct {
	Cluster map[string]bool            `json:"cluster"`
	Index   map[string]map[string]bool `json:"index"`
}

func (s *Source) esPrivileges(ctx context.Context) ([]string, error) {
	b, err := marshalChecked(PrivilegesBody{Cluster: writeCluster,
		Index: []IndexPrivileges{{Names: strings.Split(s.seg, ","), Privileges: append([]string{"read"}, writeIndex...)}}})
	if err != nil {
		return nil, err
	}
	body, err := s.do(ctx, http.MethodGet, egress.ElasticPrivilegesPath, nil, b)
	if err != nil {
		return nil, err
	}
	var r hasPrivilegesResponse
	if json.Unmarshal(body, &r) != nil || r.Cluster == nil || r.Index == nil {
		return nil, errResponse
	}
	var write []string
	for _, p := range writeCluster {
		if r.Cluster[p] {
			write = append(write, "cluster:"+p)
		}
	}
	for _, name := range strings.Split(s.seg, ",") {
		privs, ok := r.Index[name]
		if !ok {
			return nil, errResponse
		}
		if !privs["read"] {
			return nil, fmt.Errorf("%w %s", errCannotRead, name)
		}
		for _, p := range writeIndex {
			if privs[p] {
				write = append(write, name+":"+p)
			}
		}
	}
	return write, nil
}

type authInfoResponse struct {
	Roles []string `json:"roles"`
}

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
	var write []string
	if info.Flavour == FlavourOpenSearch {
		write, err = s.osPrivileges(ctx)
	} else {
		write, err = s.esPrivileges(ctx)
	}
	switch {
	case err == nil:
		info.Verified, info.Write = true, write
	case errors.Is(err, errCannotRead):
		return info, err
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
	sch := source.Schema{Kind: Kind, Format: s.o.Parser.Options().Format}
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
		info := source.FieldInfo{Name: n, Trusted: s.trusted(n)}
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
