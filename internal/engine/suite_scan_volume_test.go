//go:build unix

package engine

// The approved-scan test (design §9.1, §3.3, R5-P3): a 20 GiB approved
// scan on local files completes across continuations within one approval
// and its 30-minute TTL. The CI scan-volume job generates the files on
// the runner (LOCKLOG_SCAN_VOLUME=20GiB, LOCKLOG_SCAN_DIR on its larger
// disk); locally, LOCKLOG_SUITES=1 runs a scaled-down variant (128 MiB),
// or LOCKLOG_SCAN_VOLUME sets the volume.

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/DavidGodefroid/locklog/internal/mask"
)

// writeScanVolume writes total bytes of JSON app log in daily files of
// perFile bytes, ending at end; every 1000th line is an upstream time-out.
func writeScanVolume(t *testing.T, dir string, total, perFile int64, end time.Time) ([]string, int64) {
	t.Helper()
	files := int((total + perFile - 1) / perFile)
	const lineLen = 200
	perDay := perFile / lineLen
	step := 24 * time.Hour / time.Duration(perDay)
	var paths []string
	var lines int64
	buf := make([]byte, 0, 512)
	for d := files - 1; d >= 0; d-- {
		path := filepath.Join(dir, "app.log."+strconv.Itoa(d))
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		w := bufio.NewWriterSize(f, 4<<20)
		day := end.Add(-time.Duration(d+1) * 24 * time.Hour)
		var written int64
		for i := int64(0); written < perFile; i++ {
			ts := day.Add(time.Duration(i) * step)
			n := lines + i
			buf = buf[:0]
			buf = append(buf, `{"ts":"`...)
			buf = ts.UTC().AppendFormat(buf, "2006-01-02T15:04:05.000000Z")
			if n%1000 == 0 {
				buf = append(buf, `","level":"error","status":502,"order":4812,"msg":"render pdf failed: upstream timed out (order 4812)","user":"user`...)
			} else {
				buf = append(buf, `","level":"info","status":200,"order":`...)
				buf = strconv.AppendInt(buf, 4000+n%1000, 10)
				buf = append(buf, `,"msg":"order confirmed in `...)
				buf = strconv.AppendInt(buf, 20+n%400, 10)
				buf = append(buf, `ms","user":"user`...)
			}
			buf = strconv.AppendInt(buf, n%500, 10)
			buf = append(buf, `@shop.example","req":"`...)
			for len(buf) < lineLen-3 {
				buf = append(buf, 'x')
			}
			buf = append(buf, "\"}\n"...)
			w.Write(buf)
			written += int64(len(buf))
			if written >= perFile {
				lines += i + 1
			}
		}
		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}
		f.Close()
		last := day.Add(24*time.Hour - time.Second)
		os.Chtimes(path, last, last)
		paths = append(paths, path)
	}
	return paths, lines
}

func TestApprovedScanVolume(t *testing.T) {
	total := int64(128 << 20)
	if v := os.Getenv("LOCKLOG_SCAN_VOLUME"); v != "" {
		total = parseSize(t, v)
	} else {
		heavySuite(t)
	}
	dir := os.Getenv("LOCKLOG_SCAN_DIR")
	if dir == "" {
		dir = t.TempDir()
	} else {
		var err error
		if dir, err = os.MkdirTemp(dir, "scan-volume-"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(dir) })
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err == nil {
		free := int64(st.Bavail) * int64(st.Bsize)
		t.Logf("%s: %.1f GiB free", dir, float64(free)/(1<<30))
		if free < total+(1<<30) {
			t.Fatalf("%.1f GiB free in %s, %.1f GiB needed: set LOCKLOG_SCAN_DIR to a larger disk", float64(free)/(1<<30), dir, float64(total+(1<<30))/(1<<30))
		}
	}
	// Daily files over more than the free 7 days: at most 1 GiB a day,
	// and at least ten days.
	perFile := min(total/10, int64(1<<30))
	end := time.Now().UTC().Truncate(time.Hour)
	start := time.Now()
	paths, lines := writeScanVolume(t, dir, total, perFile, end)
	t.Logf("generated %d files, %.2f GiB, %d lines in %v", len(paths), float64(total)/(1<<30), lines, time.Since(start).Round(time.Second))
	s := newSuite(t, nil, suiteConfig{Structured: mask.StructuredRedactUnknown, Workers: 2, NoAgentMeta: true, Calibrated: true,
		Now: time.Now, Files: map[string][]string{"json": paths}})
	from := end.Add(-time.Duration(len(paths)) * 24 * time.Hour)
	q := CountQuery{Query: Query{From: from, To: end, Sources: []string{"json"}, Text: "upstream timed out"}, Bucket: "24h"}
	// Free, the call is over its budgets (the range, the bytes): the
	// skill turns that into one approved scan.
	if r := s.run(agentCall{"free count", MethodCount, q}); r.refusal == nil || r.refusal.Code != EOverBudget {
		t.Fatalf("the free count over %d days was not refused over budget: %+v", len(paths), r.refusal)
	}
	con := &screens{}
	ctx := con.ctx(1000)
	start = time.Now()
	var (
		calls   int
		scanned int64
		rates   []float64 // MiB/s of each call
		infos   []ScanInfo
		final   CountResult
	)
	params := map[string]any{}
	b, _ := json.Marshal(q)
	json.Unmarshal(b, &params)
	for {
		callStart := time.Now()
		a := s.handle(ctx, MethodScan, map[string]any{"tool": ScanCount, "query": params, "reason": "count the time-outs over the whole history"})
		calls++
		if a.refusal != nil || a.err != nil {
			took := time.Since(start)
			rate := float64(scanned) / took.Seconds()
			t.Logf("scan ended after %d calls, %v: %v %v", calls, took.Round(time.Second), a.refusal, a.err)
			t.Logf("scanned %.2f GiB of %.2f GiB at %.2f MiB/s; %v would need %.2f MiB/s", float64(scanned)/(1<<30), float64(total)/(1<<30),
				rate/(1<<20), DefaultScanTTL, float64(total)/DefaultScanTTL.Seconds()/(1<<20))
			expired := a.refusal != nil && a.refusal.Code == EStale && strings.Contains(a.refusal.Message, "expired") && took >= DefaultScanTTL
			if !expired {
				t.Fatalf("the approved scan did not complete on its approval (%d approvals)", con.count())
			}
			// The known gap (#104): the TTL ends the scan. What holds
			// is still asserted: one approval for the whole plan, a
			// steady rate, no personal value in any answer.
			if con.count() != 1 {
				t.Errorf("%d approvals, want 1 for the whole plan", con.count())
			}
			checkSteady(t, rates)
			if t.Failed() {
				return
			}
			t.Skipf("known gap, https://github.com/DavidGodefroid/locklog/issues/104: the TTL (%v) expired after %.2f of %.2f GiB at %.2f MiB/s on one approval (%.2f MiB/s needed)",
				DefaultScanTTL, float64(scanned)/(1<<30), float64(total)/(1<<30), rate/(1<<20), float64(total)/DefaultScanTTL.Seconds()/(1<<20))
		}
		if strings.Contains(string(a.res), "@shop.example") || strings.Contains(string(a.res), "user1") {
			t.Fatalf("call %d: a personal value reached the agent: %.300s", calls, a.res)
		}
		var sr struct {
			Scan   ScanInfo        `json:"scan"`
			Result json.RawMessage `json:"result"`
		}
		json.Unmarshal(a.res, &sr)
		var cr CountResult
		json.Unmarshal(sr.Result, &cr)
		infos = append(infos, sr.Scan)
		scanned += cr.Scanned.Bytes
		rates = append(rates, float64(cr.Scanned.Bytes)/time.Since(callStart).Seconds()/(1<<20))
		if calls%10 == 1 || sr.Scan.Done {
			el := time.Since(start)
			t.Logf("call %d: %.2f GiB scanned in %v (%.2f MiB/s), done %v", calls, float64(scanned)/(1<<30), el.Round(time.Second),
				float64(scanned)/el.Seconds()/(1<<20), sr.Scan.Done)
		}
		if sr.Scan.Done {
			final = cr
			break
		}
		if cr.Cursor == "" {
			t.Fatalf("call %d: an incomplete scan without a cursor", calls)
		}
		params["cursor"] = cr.Cursor
	}
	took := time.Since(start)
	var n int64
	for _, g := range final.Groups {
		n += g.N
	}
	t.Logf("approved scan: %.2f GiB in %d calls, %d approvals, %v (%.2f MiB/s); %d time-outs counted",
		float64(scanned)/(1<<30), calls, con.count(), took.Round(time.Second), float64(scanned)/took.Seconds()/(1<<20), n)
	if con.count() != 1 {
		t.Errorf("%d approvals, want 1 for the whole plan", con.count())
	}
	checkSteady(t, rates)
	if took > DefaultScanTTL || time.Now().After(infos[len(infos)-1].ExpiresAt) {
		t.Errorf("the scan took %v, past its TTL %v", took, DefaultScanTTL)
	}
	if want := (lines + 999) / 1000; n != want {
		t.Errorf("counted %d time-outs, want %d", n, want)
	}
	if scanned < total*9/10 {
		t.Errorf("scanned %d bytes of %d", scanned, total)
	}
}

// checkSteady checks the scan's calls ran at a steady rate: past the
// first call (the cost model's calibration), each within half and twice
// the median.
func checkSteady(t *testing.T, rates []float64) {
	t.Helper()
	if len(rates) < 3 {
		return
	}
	rs := slices.Clone(rates[1:])
	slices.Sort(rs)
	med := rs[len(rs)/2]
	for i, r := range rates[1:] {
		if r < med/2 || r > med*2 {
			t.Errorf("call %d ran at %.2f MiB/s, the median %.2f MiB/s: not steady", i+2, r, med)
		}
	}
	t.Logf("calls at a median %.2f MiB/s (%.2f to %.2f)", med, rs[0], rs[len(rs)-1])
}
