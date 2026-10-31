//go:build unix

package engine

// TestSuiteLokiDebug (CI debug step only, LOCKLOG_SUITE_LOKI_DEBUG=1 with
// LOCKLOG_SUITE_LOKI_URL): pushes a few suite entries in several shapes to
// the real Loki and logs what Loki answers to the push and to each way of
// reading them back.

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func lokiGet(t *testing.T, base, path string) string {
	resp, err := http.Get(base + path)
	if err != nil {
		return "error: " + err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	s := string(b)
	if len(s) > 1500 {
		s = s[:1500] + "…"
	}
	return fmt.Sprintf("%d %s", resp.StatusCode, s)
}

func TestSuiteLokiDebug(t *testing.T) {
	base := strings.TrimSuffix(os.Getenv("LOCKLOG_SUITE_LOKI_URL"), "/")
	if base == "" || os.Getenv("LOCKLOG_SUITE_LOKI_DEBUG") != "1" {
		t.Skip("debug step of the CI suites job")
	}
	lokiPushLog = func(status int, h http.Header, body []byte) {
		t.Logf("push: %d %v %q", status, h, body)
	}
	defer func() { lokiPushLog = nil }()
	recs := leakCorpus(16)[srcLoki][:20]
	now := time.Now().UTC().Truncate(time.Second)
	for _, tc := range []struct {
		name          string
		recent, plain bool
	}{
		{"suite shape, suite dates", false, false},
		{"plain shape, suite dates", false, true},
		{"suite shape, recent", true, false},
		{"plain shape, recent", true, true},
	} {
		run := strings.NewReplacer(" ", "", ",", "-").Replace(tc.name) + strconv.FormatInt(now.Unix()%100000, 10)
		var rs []suiteRecord
		for i, r := range recs {
			if tc.recent {
				r.TS = now.Add(-time.Hour + time.Duration(i)*time.Second)
			}
			rs = append(rs, r)
		}
		es := lokiEntries(rs, run)
		if tc.plain {
			for i := range es {
				es[i].labels = map[string]string{"env": "suite", "run": run}
				es[i].meta = nil
			}
		}
		streams := map[string]*pushStream{}
		var order []*pushStream
		for _, e := range es {
			k := lokiLabelsKey(e.labels)
			if streams[k] == nil {
				streams[k] = &pushStream{Stream: e.labels}
				order = append(order, streams[k])
			}
			v := []any{strconv.FormatInt(e.ts, 10), e.line}
			if e.meta != nil {
				v = append(v, e.meta)
			}
			streams[k].Values = append(streams[k].Values, v)
		}
		t.Logf("%s: run %s, %d entries in %d streams, first at %v", tc.name, run, len(es), len(order), time.Unix(0, es[0].ts).UTC())
		if err := lokiPush(base, order); err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		time.Sleep(2 * time.Second)
		from, to := time.Unix(0, es[0].ts).Add(-time.Minute), time.Unix(0, es[len(es)-1].ts).Add(time.Minute)
		sel := urlEscape(`{run="` + run + `"}`)
		for i := range 3 {
			at := to.Add(time.Duration(i) * time.Millisecond)
			q := urlEscape(fmt.Sprintf("sum by () (count_over_time({run=%q} [%ds]))", run, int64(at.Sub(from)/time.Second)))
			t.Logf("%s: instant count at +%dms: %s", tc.name, i, lokiGet(t, base, "/loki/api/v1/query?query="+q+"&time="+strconv.FormatInt(at.UnixNano(), 10)))
		}
		t.Logf("%s: query_range: %s", tc.name, lokiGet(t, base, fmt.Sprintf("/loki/api/v1/query_range?query=%s&start=%d&end=%d&limit=5&direction=forward", sel, from.UnixNano(), to.UnixNano())))
		q := urlEscape(fmt.Sprintf("sum by () (count_over_time({run=%q} [60s]))", run))
		t.Logf("%s: range count (step 60): %s", tc.name, lokiGet(t, base, fmt.Sprintf("/loki/api/v1/query_range?query=%s&start=%d&end=%d&step=60", q, from.UnixNano(), to.UnixNano())))
		t.Logf("%s: series: %s", tc.name, lokiGet(t, base, fmt.Sprintf("/loki/api/v1/series?match[]=%s&start=%d&end=%d", sel, from.UnixNano(), to.UnixNano())))
	}
	t.Logf("labels: %s", lokiGet(t, base, "/loki/api/v1/labels"))
	t.Logf("run values: %s", lokiGet(t, base, "/loki/api/v1/label/run/values"))
	t.Logf("config limits: %s", lokiGet(t, base, "/config"))
}
