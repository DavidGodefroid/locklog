//go:build linux

package journald

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/locklog/internal/source"
)

// TestLiveJournal reads the host's journal (the CI runner's journald):
// an entry written with systemd-cat comes back with journalctl's fields.
// It runs only with LOCKLOG_JOURNALD_IT=1 (the integration CI job).
func TestLiveJournal(t *testing.T) {
	if os.Getenv("LOCKLOG_JOURNALD_IT") != "1" {
		t.Skip("set LOCKLOG_JOURNALD_IT=1 to read the host journal")
	}
	b := make([]byte, 8)
	rand.Read(b)
	marker := "locklog-it-" + hex.EncodeToString(b)
	cmd := exec.Command("systemd-cat", "-t", "locklog-it", "-p", "warning")
	cmd.Stdin = strings.NewReader(marker + " from user it@example.com\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("systemd-cat: %v %s", err, out)
	}
	var ref map[string]any
	deadline := time.Now().Add(20 * time.Second)
	for ref == nil && time.Now().Before(deadline) {
		out, _ := exec.Command("journalctl", "-o", "json", "--all", "--no-pager", "SYSLOG_IDENTIFIER=locklog-it").Output()
		for _, l := range strings.Split(string(out), "\n") {
			if strings.Contains(l, marker) {
				json.Unmarshal([]byte(l), &ref)
			}
		}
		if ref == nil {
			time.Sleep(time.Second)
		}
	}
	if ref == nil {
		t.Fatal("journalctl never showed the entry")
	}
	// A non-root writer's entries go to its user journal.
	s := newSource(t, Options{Roots: []string{"/var/log/journal", "/run/log/journal"}, UserJournals: true})
	now := time.Now()
	recs := scanAll(t, s, source.Range{From: now.Add(-10 * time.Minute), To: now.Add(time.Minute)})
	var found *source.RawRecord
	for i := range recs {
		if strings.Contains(recs[i].Event.Raw, marker) {
			found = &recs[i]
		}
	}
	if found == nil {
		t.Fatalf("the source did not find the entry among %d records", len(recs))
	}
	for _, m := range found.Event.Fields {
		if journalName(m.Key) && ref[m.Key] != m.Value.Str {
			t.Fatalf("%s: %q, journalctl %v", m.Key, m.Value.Str, ref[m.Key])
		}
	}
	for _, k := range []string{"SYSLOG_IDENTIFIER", "PRIORITY", "_PID", "_TRANSPORT"} {
		if v, ok := ref[k]; ok {
			got := ""
			for _, m := range found.Event.Fields {
				if m.Key == k {
					got = m.Value.Str
				}
			}
			if got != v {
				t.Fatalf("%s missing or different: %q vs %v", k, got, v)
			}
		}
	}
	for _, m := range found.Event.Fields {
		if NeverServed(m.Key) {
			t.Fatalf("%s served", m.Key)
		}
	}
}
