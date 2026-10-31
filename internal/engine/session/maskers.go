package session

import (
	"strings"

	"github.com/DavidGodefroid/lockkit/pii"

	"github.com/DavidGodefroid/locklog/internal/config"
	"github.com/DavidGodefroid/locklog/internal/mask"
	"github.com/DavidGodefroid/locklog/internal/parse"
)

// maskers is the engine's masker: one mask.Masker per source, as trusted
// fields and attribute keys are a source's own, all on one pseudonym
// epoch and one set of rules (a value has the same pseudonym in every
// source). base trusts nothing: it masks text outside a record, and the
// records of a source it does not know.
type maskers struct {
	base *mask.Masker
	by   map[string]*mask.Masker
}

// maskerOptions are the masker options of source s of profile pr.
func maskerOptions(pr config.Profile, s config.Source, rules *mask.Rules, values mask.Finder, ep *pii.Pseudonymizer) mask.Options {
	return mask.Options{Structured: pr.Structured, Values: values, Trusted: s.TrustedFields(), AttrKeys: attrKeys(s),
		Rules: rules, Pseudonyms: ep}
}

func newMaskers(pr config.Profile, rules *mask.Rules, values mask.Finder, ep *pii.Pseudonymizer) (*maskers, error) {
	base, err := mask.New(mask.Options{Structured: pr.Structured, Values: values, Rules: rules, Pseudonyms: ep})
	if err != nil {
		return nil, err
	}
	ms := &maskers{base: base, by: map[string]*mask.Masker{}}
	for _, s := range pr.Sources {
		m, err := mask.New(maskerOptions(pr, s, rules, values, ep))
		if err != nil {
			return nil, err
		}
		ms.by[s.Name] = m
	}
	return ms, nil
}

func (ms *maskers) of(src string) *mask.Masker {
	if m, ok := ms.by[src]; ok {
		return m
	}
	return ms.base
}

// Mask implements engine.Masker.
func (ms *maskers) Mask(src string, ev parse.Event) mask.Record { return ms.of(src).Mask(src, ev) }

// Text implements engine.Masker.
func (ms *maskers) Text(s string) string { return ms.base.Text(s) }

// TrustedValue implements engine.Masker.
func (ms *maskers) TrustedValue(src, path, v string) string {
	return ms.of(src).TrustedValue(src, path, v)
}

// MaskClear implements engine.ClearMasker.
func (ms *maskers) MaskClear(src string, ev parse.Event) (mask.Record, map[string]string) {
	return ms.of(src).MaskClear(src, ev)
}

// Lookup implements engine.Lookuper: a value is looked up as free text,
// with the base masker (a pseudonym is the same in every source).
func (ms *maskers) Lookup(kind, value string) (string, error) { return ms.base.Lookup(kind, value) }

// DetectorKinds implements engine.Lookuper.
func (ms *maskers) DetectorKinds() []string { return ms.base.DetectorKinds() }

// Epoch implements engine.Masker.
func (ms *maskers) Epoch() string { return ms.base.Epoch() }

// nameMasked reports a clear field path one of whose keys the masker shows
// masked (⟦key:ID⟧: a key holding a secret or a personal value): asked by
// its clear name, it would tell that the key exists.
func (ms *maskers) nameMasked(src, p string) bool {
	m := ms.of(src)
	if m.Text(p) != p {
		return true // a key holding dots
	}
	for _, k := range strings.Split(p, ".") {
		if m.Text(k) != k {
			return true
		}
	}
	return false
}
