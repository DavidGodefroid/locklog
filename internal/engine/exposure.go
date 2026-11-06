package engine

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ExposureCount counts, for each pseudonym, the distinct records holding
// it returned to agents in epoch (the console's count, from the calls it
// answered and audited): whether the counts are exact (false: lower
// bounds) and since when it counts.
type ExposureCount func(epoch string, pseudonyms []string) (counts []int, exact bool, since time.Time)

type exposureKey struct{}

// WithExposureCount attaches the console's exposure count to ctx: the
// unmask screen shows it.
func WithExposureCount(ctx context.Context, f ExposureCount) context.Context {
	return context.WithValue(ctx, exposureKey{}, f)
}

func exposureFrom(ctx context.Context) ExposureCount {
	f, _ := ctx.Value(exposureKey{}).(ExposureCount)
	return f
}

// RefRecord opens a sealed ref of a returned record: a key of the record
// (keyed: the same record at the same place, the same key; it says
// nothing of its text) and the epoch of its pseudonyms. ok is false for a
// ref this engine cannot open.
func (e *Engine) RefRecord(ref string) (key, epoch string, ok bool) {
	var st refState
	if e.o.Sealer.Open("Lr1", ref, &st) != nil {
		return "", "", false
	}
	d := e.o.Sealer.Digest("locklog/exposed/v1", []byte(st.Source), []byte(st.Stream), []byte(strconv.FormatInt(st.Offset, 10)), []byte(st.Digest))
	return d[:min(len(d), 16)], st.Epoch, true
}

// exposureLine is the unmask screen's count of the records holding each
// pseudonym that agents were given in this epoch.
func (e *Engine) exposureLine(ctx context.Context, pseudonyms []string) string {
	f := exposureFrom(ctx)
	if f == nil {
		return "returned to agents in this epoch: not counted by this console"
	}
	counts, exact, since := f(e.o.Masker.Epoch(), pseudonyms)
	parts := make([]string, len(pseudonyms))
	for i, p := range pseudonyms {
		n := fmt.Sprintf("%d", counts[i])
		if !exact {
			n = "at least " + n
		}
		unit := "records"
		if counts[i] == 1 && exact {
			unit = "record"
		}
		parts[i] = fmt.Sprintf("%s in %s %s", p, n, unit)
	}
	return "returned to agents in this epoch: " + strings.Join(parts, ", ") + " (counted by this console since " + since.UTC().Format(time.RFC3339) + ")"
}
