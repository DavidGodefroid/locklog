package engine

import (
	"fmt"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DavidGodefroid/locklog/internal/parse"
	"github.com/DavidGodefroid/locklog/internal/source"
)

// Cost model (design §3.3): the engine sizes the work of a call from a
// worst-case cost per byte, measured on a fixed synthetic corpus built at the
// per-event caps (256 KiB events, nesting depth 64, every value a detector
// hit), so the work a call does never depends on the agent's predicates. It
// is calibrated at start, hourly, and at once after an overrun.

const (
	// calibrationBudget bounds one calibration.
	calibrationBudget = 5 * time.Second
	// calibrationEvery is the periodic recalibration.
	calibrationEvery = time.Hour
	// costSafety multiplies the measured cost.
	costSafety = 1.25
	// minCostPerByte guards against a nonsensical measurement.
	minCostPerByte = 0.5 // ns
)

// MaskFunc masks one parsed event (the console passes its masker); the
// result is ignored by calibration.
type MaskFunc func(ev parse.Event)

// CostModel is the calibrated worst-case cost.
type CostModel struct {
	mu        sync.Mutex
	nsPerByte float64
	at        time.Time
	mask      MaskFunc
	parser    *parse.Parser
	now       func() time.Time
	corpus    []string
	fixed     bool // tests: never recalibrate
	workers   int
	// running is the single-flight guard of background calibrations.
	running atomic.Bool
}

// DefaultNsPerByte is the worst-case cost per byte and core before the
// first calibration (S4: the slowest corpus, encoded text, 0.2 MB/s/core).
const DefaultNsPerByte = 5000

// NewCostModel calibrates once; workers is the number of masking workers of
// a call (the per-call cost is the per-core cost divided by it).
func NewCostModel(p *parse.Parser, m MaskFunc, workers int, now func() time.Time) *CostModel {
	c := &CostModel{mask: m, parser: p, now: now, corpus: worstCaseCorpus(), workers: max(1, workers),
		nsPerByte: DefaultNsPerByte / float64(max(1, workers))}
	c.Calibrate()
	return c
}

// Recalibrate starts a calibration in the background unless one is already
// running, and returns at once: a query never waits for one (it may take up
// to calibrationBudget), and concurrent queries start at most one.
func (c *CostModel) Recalibrate() {
	if c.fixed || !c.running.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer c.running.Store(false)
		c.Calibrate()
	}()
}

// Calibrate measures the worst-case cost per byte on the fixed corpus,
// synchronously (at start; queries use Recalibrate).
func (c *CostModel) Calibrate() {
	if c.fixed {
		return
	}
	start := time.Now()
	worst := 0.0
	for _, doc := range c.corpus {
		t := time.Now()
		ev := c.parser.Line(doc)
		c.mask(ev)
		ns := float64(time.Since(t).Nanoseconds()) / float64(len(doc))
		worst = math.Max(worst, ns)
		if time.Since(start) > calibrationBudget {
			break
		}
	}
	c.mu.Lock()
	c.nsPerByte = math.Max(worst*costSafety/float64(max(1, c.workers)), minCostPerByte)
	c.at = c.now()
	c.mu.Unlock()
}

// NsPerByte returns the cost per byte, recalibrating hourly in the
// background (the current value serves until the new one is measured).
func (c *CostModel) NsPerByte() float64 {
	c.mu.Lock()
	stale := c.now().Sub(c.at) > calibrationEvery
	ns := c.nsPerByte
	c.mu.Unlock()
	if stale {
		c.Recalibrate()
	}
	return ns
}

// Budget returns how many bytes fit in d.
func (c *CostModel) Budget(d time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	return int64(float64(d.Nanoseconds()) / c.NsPerByte())
}

// Time returns the worst-case time of n bytes.
func (c *CostModel) Time(n int64) time.Duration {
	return time.Duration(float64(n) * c.NsPerByte())
}

// String reports the model for status screens.
func (c *CostModel) String() string {
	return fmt.Sprintf("%.1f ns/byte (worst case)", c.NsPerByte())
}

// worstCaseCorpus returns events at the caps, dense in detector hits: free
// text full of e-mails, IPs, IBANs, cards, tokens and percent/JSON-escaped
// encodings; a JSON object of depth 64 whose leaves are all personal; and a
// wide flat logfmt line.
func worstCaseCorpus() []string {
	hits := []string{
		"anna.smith%d@example.com", "203.0.113.%d", "BE71096123456769", "4111 1111 1111 1111",
		"+32 470 12 34 %02d", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
		"Bearer abcdef0123456789abcdef0123456789", "j%%40hn%d%%40example.com", "\\u0040x%d@example.org",
	}
	var text strings.Builder
	for i := 0; text.Len() < parse.MaxEventBytes-200; i++ {
		h := hits[i%len(hits)]
		if strings.Contains(h, "%") {
			h = fmt.Sprintf(h, i%100)
		}
		text.WriteString("user ")
		text.WriteString(h)
		text.WriteString(" password=hunter2 ")
	}
	var deep strings.Builder
	deep.WriteString("{")
	for d := 0; d < parse.MaxDepth-2; d++ {
		fmt.Fprintf(&deep, `"email_%d":"x%d@example.com","n%d":{`, d, d, d)
	}
	deep.WriteString(`"ip":"198.51.100.7"`)
	deep.WriteString(strings.Repeat("}", parse.MaxDepth-2))
	for deep.Len() < parse.MaxEventBytes-200 {
		fmt.Fprintf(&deep, `,"k%d":"user%d@example.com 203.0.113.9"`, deep.Len(), deep.Len())
	}
	deep.WriteString("}")
	var flat strings.Builder
	for i := 0; flat.Len() < parse.MaxEventBytes-200; i++ {
		fmt.Fprintf(&flat, "email%d=u%d@example.com ip%d=192.0.2.%d ", i, i, i, i%250)
	}
	return []string{text.String(), deep.String(), flat.String()}
}

// granuleGroups splits the granules of a chunk, from index from, into
// groups whose worst-case time each fits within per; a granule larger than
// per is a group of its own, and so is a granule of unknown bytes (a remote
// slice, sized only by its fetch): stopping points then fall on its
// boundaries, never after a run of them fetched as one.
func granuleGroups(c source.Chunk, from int, per int64) [][2]int {
	var out [][2]int
	i := from
	for i < len(c.Granules) {
		j, n := i, int64(0)
		for j < len(c.Granules) {
			b := granuleBytes(c.Granules[j], c)
			if j > i && (n+b > per || b == 0 || n == 0) {
				break
			}
			n += b
			j++
		}
		out = append(out, [2]int{i, j})
		i = j
	}
	return out
}

// granuleBytes is the planned bytes of a granule of c: its own; for an
// open-ended granule of a compressed stream not yet measured, the chunk's
// estimate; for a granule of unknown bytes in a chunk of known bytes, its
// share of the chunk (never a whole chunk as one group); else 0, unknown
// before the fetch (remote).
func granuleBytes(g source.Granule, c source.Chunk) int64 {
	switch {
	case g.Bytes > 0:
		return g.Bytes
	case g.End == math.MaxInt64:
		return c.Bytes
	case c.Bytes > 0:
		return max(c.Bytes/int64(len(c.Granules)), 1)
	}
	return 0
}
