package egress

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/DavidGodefroid/locklog/internal/config"
)

// ValidIndex reports whether name is an index name or trailing-'*' pattern
// a source may name (config.ValidIndex: lower-case letters, digits, '.',
// '_' and '-', starting with a letter or digit, so no hidden or system
// index, no "_all", no remote cluster "a:b"; at most one '*', as its last
// character, a pattern over the open, non-hidden indices).
func ValidIndex(name string) bool { return config.ValidIndex(name) }

// IndexSegment validates indices and returns the path segment that names
// them (sorted, comma-separated).
func IndexSegment(indices []string) (string, error) {
	if len(indices) == 0 {
		return "", errors.New("egress: an Elasticsearch source needs at least one index")
	}
	for _, i := range indices {
		if !ValidIndex(i) {
			return "", fmt.Errorf("egress: invalid index name %q (lower-case letters, digits, '.', '_' and '-', starting with a letter or digit, at most a trailing '*')", i)
		}
	}
	s := slices.Clone(indices)
	slices.Sort(s)
	return strings.Join(slices.Compact(s), ","), nil
}

// ElasticRoutes are the only Elasticsearch / OpenSearch requests locklog
// sends: searches, counts, field capabilities, mappings and settings of the
// source's own indices (the segment is literal: no other index is
// reachable), the root (flavour and version), and the read-only privilege
// checks of each flavour: Elasticsearch's grants of the user and what the
// source's indices resolve to, the OpenSearch security plugin's roles of
// the user (authinfo: any authenticated user may read it).
func ElasticRoutes(indices []string) (*Allowlist, error) {
	seg, err := IndexSegment(indices)
	if err != nil {
		return nil, err
	}
	open := map[string]string{"expand_wildcards": "open"}
	return NewAllowlist(
		Route{http.MethodPost, "/" + seg + "/_search", open},
		Route{http.MethodPost, "/" + seg + "/_count", open},
		Route{http.MethodGet, "/" + seg + "/_field_caps", map[string]string{"expand_wildcards": "open", "fields": ""}},
		Route{http.MethodGet, "/" + seg + "/_mapping", open},
		Route{http.MethodGet, "/" + seg + "/_settings", map[string]string{"expand_wildcards": "open", "flat_settings": "true", "include_defaults": "true"}},
		Route{http.MethodGet, "/", nil},
		Route{http.MethodGet, ElasticUserPrivilegesPath, nil},
		Route{http.MethodGet, "/_resolve/index/" + seg, open},
		Route{http.MethodGet, OpenSearchAuthInfoPath, nil},
	), nil
}

// The privilege checks: Elasticsearch's grants of the user, the
// OpenSearch security plugin's authinfo.
const (
	ElasticUserPrivilegesPath = "/_security/user/_privileges"
	OpenSearchAuthInfoPath    = "/_plugins/_security/authinfo"
)

// ElasticProbePath is the data endpoint the unauthenticated-read check
// reads: the mappings of the source's indices (field names: data).
func ElasticProbePath(indices []string) (string, error) {
	seg, err := IndexSegment(indices)
	if err != nil {
		return "", err
	}
	return "/" + seg + "/_mapping", nil
}

// ElasticData recognizes a mapping answer: a JSON object of at least one
// index, each an object holding "mappings". An empty object (no index
// matched the pattern) is data too: the read was allowed.
func ElasticData(body []byte) bool {
	var v map[string]json.RawMessage
	if json.Unmarshal(body, &v) != nil || v == nil {
		return false
	}
	for _, raw := range v {
		var idx map[string]json.RawMessage
		if json.Unmarshal(raw, &idx) != nil {
			return false
		}
		if _, ok := idx["mappings"]; !ok {
			return false
		}
	}
	return true
}

// CheckElasticUnauthenticated is the production check of an Elasticsearch
// or OpenSearch source: it refuses the source when its mappings read
// without credentials.
func CheckElasticUnauthenticated(ctx context.Context, c *Client, production bool, indices []string) error {
	path, err := ElasticProbePath(indices)
	if err != nil {
		return err
	}
	return CheckUnauthenticatedAt(ctx, c, production, path, ElasticData)
}
