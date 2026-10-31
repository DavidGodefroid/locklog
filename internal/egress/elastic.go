package egress

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
)

// indexRe is an Elasticsearch / OpenSearch index, alias or data stream
// name locklog accepts: lower-case letters, digits, '.', '_' and '-',
// starting with a letter or digit (no hidden or system index, no "_all",
// no remote cluster "a:b"), with at most one '*', as its last character (a
// pattern over the open, non-hidden indices).
var indexRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,253}\*?$`)

// ValidIndex reports whether name is an index name or trailing-'*' pattern
// a source may name.
func ValidIndex(name string) bool {
	return indexRe.MatchString(name) && name != "." && name != ".." && !strings.Contains(name, "..")
}

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
// sends: searches, counts, field capabilities and mappings of the
// source's own indices (the segment is literal: no other index is
// reachable), the root (flavour and version), and the read-only privilege
// checks of each flavour.
func ElasticRoutes(indices []string) (*Allowlist, error) {
	seg, err := IndexSegment(indices)
	if err != nil {
		return nil, err
	}
	return NewAllowlist(
		Route{http.MethodPost, "/" + seg + "/_search"},
		Route{http.MethodPost, "/" + seg + "/_count"},
		Route{http.MethodGet, "/" + seg + "/_field_caps"},
		Route{http.MethodGet, "/" + seg + "/_mapping"},
		Route{http.MethodGet, "/"},
		Route{http.MethodGet, ElasticPrivilegesPath},
		Route{http.MethodGet, ElasticUserPrivilegesPath},
		Route{http.MethodGet, OpenSearchAuthInfoPath},
	), nil
}

// The privilege checks: Elasticsearch's has_privileges (a GET with a
// body) and the user's own grants, the OpenSearch security plugin's
// authinfo.
const (
	ElasticPrivilegesPath     = "/_security/user/_has_privileges"
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
