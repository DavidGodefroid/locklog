package mask

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// MaskClear masks as Mask does and maps each value pseudonym of the record
// to its clear value; field names and secrets have none.
func TestMaskClear(t *testing.T) {
	m := newMasker(t, Options{Structured: StructuredDetect})
	ev := event(t, `{"msg":"mail to jane@example.com from 8.8.8.8","token":"ghp_0123456789abcdefghijABCDEFGHIJ012345","jane.doe@example.com":1}`)
	rec, clear := m.MaskClear("app", ev)
	plain := m.Mask("app", ev)
	a, _ := rec.MarshalJSON()
	b, _ := plain.MarshalJSON()
	if string(a) != string(b) {
		t.Fatalf("MaskClear differs from Mask:\n%s\n%s", a, b)
	}
	vals := map[string]bool{}
	for tok, v := range clear {
		if !strings.Contains(string(a), tok) {
			t.Errorf("%s is not in the record", tok)
		}
		vals[v] = true
		if strings.HasPrefix(tok, Open+KeyKind+":") || strings.Contains(v, "ghp_") {
			t.Errorf("%s → %q revealed", tok, v)
		}
	}
	if !vals["jane@example.com"] || !vals["8.8.8.8"] {
		t.Fatalf("clear values %v", clear)
	}
}

// Lookup resolves a clear value of a detector kind to the pseudonym the
// records show, and refuses other kinds, secrets and partial values.
func TestLookup(t *testing.T) {
	m := newMasker(t, Options{Structured: StructuredDetect})
	tok, err := m.Lookup("email", "jane@example.com")
	if err != nil {
		t.Fatal(err)
	}
	rec := m.Mask("app", event(t, `{"msg":"mail to jane@example.com"}`))
	if !strings.Contains(rec.Message(), tok) {
		t.Fatalf("lookup %s, record %s", tok, rec.Message())
	}
	if !slices.Contains(m.DetectorKinds(), "email") || slices.Contains(m.DetectorKinds(), "secret") {
		t.Fatalf("kinds %v", m.DetectorKinds())
	}
	for _, tc := range []struct {
		kind, value string
		want        error
	}{
		{KeyKind, "x", ErrLookupKind},
		{PersonalKind, "jane", ErrLookupKind},
		{"secret", "x", ErrLookupKind},
		{"ip", "jane@example.com", ErrLookupValue},
		{"email", "mail jane@example.com", ErrLookupValue},
		{"email", "jane@example.com bob@example.com", ErrLookupValue},
		{"email", "ghp_0123456789abcdefghijABCDEFGHIJ012345", ErrLookupSecret},
	} {
		if _, err := m.Lookup(tc.kind, tc.value); !errors.Is(err, tc.want) {
			t.Errorf("Lookup(%q, %q) = %v, want %v", tc.kind, tc.value, err, tc.want)
		}
	}
	// A masker whose value finder is not a detector set resolves no kind.
	o := Options{Values: finders{}, Pseudonyms: epoch(t)}
	if m2, _ := New(o); m2.DetectorKinds() != nil {
		t.Fatal("kinds of a custom finder")
	}
}
