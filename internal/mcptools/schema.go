package mcptools

import (
	"github.com/google/jsonschema-go/jsonschema"
)

// Ops are the predicate operators.
var Ops = []any{"=", "!=", "in", "exists", "<", "<=", ">", ">=", "contains", "matches"}

// Input bounds the schemas state (the console checks them again).
const (
	maxLimit    = 200
	maxValue    = 1024 // a predicate value, in characters
	maxPattern  = 256  // a PII rule pattern
	maxChange   = 500  // a change request (the console's own bound)
	maxRegex    = 256
	maxTop      = 100 // engine.MaxTop
	maxDuration = 16  // a duration such as 24h or 168h
	maxAround   = 50  // engine.MaxAround
	maxRef      = 4096
	maxReason   = 300 // engine.MaxReason
	maxUnmask   = 8   // engine.MaxUnmask
	maxLookup   = 10  // engine.MaxLookup
	maxLookupV  = 256 // engine.MaxLookupValue
	maxToken    = 64  // a pseudonym ⟦kind:ID⟧
	maxKind     = 32
	maxScanArgs = 16   // the keys of a scan's query
	maxTicket   = 26   // a hub ticket id (a ULID)
	maxText     = 256  // engine.MaxNeedle: a text needle, in bytes
	maxCursor   = 4100 // a sealed cursor: "Lc1." and at most 4096 base64 bytes (engine.Sealer.Open)
	maxSources  = 32   // engine.MaxSources
	maxWhere    = 32   // engine.MaxPredicates
	maxBy       = 2    // engine.MaxBy
	maxFields   = 64   // engine.MaxFields
)

// ScanTools are the tools an approved scan runs.
var ScanTools = []any{"search", "count", "patterns", "trace"}

var (
	searchSchema = inputSchema[QueryIn](func(s *jsonschema.Schema) {
		bound(s)
		tuneRange(s)
		s.Properties["limit"].Minimum, s.Properties["limit"].Maximum = ptr(1.0), ptr(float64(maxLimit))
	})
	countSchema    = inputSchema[CountIn](func(s *jsonschema.Schema) { tuneRange(s); bound(s) })
	patternsSchema = inputSchema[PatternsIn](func(s *jsonschema.Schema) {
		bound(s)
		tuneRange(s)
		s.Properties["top"].Minimum, s.Properties["top"].Maximum = ptr(1.0), ptr(float64(maxTop))
		s.Properties["baseline"].MaxLength = ptr(maxDuration)
	})
	contextSchema = inputSchema[ContextIn](func(s *jsonschema.Schema) {
		bound(s)
		s.Properties["ref"].MinLength, s.Properties["ref"].MaxLength = ptr(1), ptr(maxRef)
		for _, k := range []string{"before", "after"} {
			s.Properties[k].Minimum, s.Properties[k].Maximum = ptr(0.0), ptr(float64(maxAround))
		}
	})
	traceSchema = inputSchema[TraceIn](func(s *jsonschema.Schema) {
		bound(s)
		s.Properties["id"].MinLength, s.Properties["id"].MaxLength = ptr(1), ptr(maxValue)
		s.Properties["limit"].Minimum, s.Properties["limit"].Maximum = ptr(1.0), ptr(float64(maxLimit))
	})
	tailSchema = inputSchema[TailIn](func(s *jsonschema.Schema) {
		bound(s)
		tuneRange(s)
		s.Properties["duration"].MaxLength = ptr(maxDuration)
		s.Properties["max"].Minimum, s.Properties["max"].Maximum = ptr(1.0), ptr(float64(maxLimit))
	})
	piiAddSchema = inputSchema[PIIAddIn](func(s *jsonschema.Schema) {
		s.Properties["pattern"].MinLength, s.Properties["pattern"].MaxLength = ptr(1), ptr(maxPattern)
	})
	scanSchema = inputSchema[ScanIn](func(s *jsonschema.Schema) {
		s.Properties["tool"].Enum = ScanTools
		s.Properties["query"].MaxProperties = ptr(maxScanArgs)
		s.Properties["reason"].MaxLength = ptr(maxReason)
		s.Properties["ticket"].MaxLength = ptr(maxTicket)
	})
	unmaskSchema = inputSchema[UnmaskIn](func(s *jsonschema.Schema) {
		s.Properties["ref"].MinLength, s.Properties["ref"].MaxLength = ptr(1), ptr(maxRef)
		s.Properties["pseudonyms"].MinItems, s.Properties["pseudonyms"].MaxItems = ptr(1), ptr(maxUnmask)
		s.Properties["pseudonyms"].Items.MaxLength = ptr(maxToken)
		s.Properties["ticket"].MaxLength = ptr(maxTicket)
		s.Properties["reason"].MinLength, s.Properties["reason"].MaxLength = ptr(1), ptr(maxReason)
	})
	lookupSchema = inputSchema[LookupIn](func(s *jsonschema.Schema) {
		s.Properties["kind"].MinLength, s.Properties["kind"].MaxLength = ptr(1), ptr(maxKind)
		s.Properties["values"].MinItems, s.Properties["values"].MaxItems = ptr(1), ptr(maxLookup)
		s.Properties["values"].Items.MinLength, s.Properties["values"].Items.MaxLength = ptr(1), ptr(maxLookupV)
		s.Properties["ticket"].MaxLength = ptr(maxTicket)
		s.Properties["reason"].MaxLength = ptr(maxReason)
	})
	changeSchema = inputSchema[ChangeIn](func(s *jsonschema.Schema) {
		s.Properties["change"].MinLength, s.Properties["change"].MaxLength = ptr(1), ptr(maxChange)
	})
)

// tuneRange bounds what a search and a count share: the predicate
// operator, the value's length and the regex's.
func tuneRange(s *jsonschema.Schema) {
	pred := s.Properties["where"].Items
	pred.Properties["op"].Enum = Ops
	pred.Properties["value"].MaxLength = ptr(maxValue)
	s.Properties["regex"].MaxLength = ptr(maxRegex)
}

// bound states the console's bounds on the query parameters a schema has
// (#78): the console checks them again, but a client sees them first.
func bound(s *jsonschema.Schema) {
	for name, n := range map[string]int{"text": maxText, "last": maxDuration, "cursor": maxCursor} {
		if p := s.Properties[name]; p != nil {
			p.MaxLength = ptr(n)
		}
	}
	for name, n := range map[string]int{"sources": maxSources, "where": maxWhere, "by": maxBy, "fields": maxFields} {
		if p := s.Properties[name]; p != nil {
			p.MaxItems = ptr(n)
		}
	}
}

// inputSchema is the schema inferred from T, tuned. T is a fixed type, so
// an error is a programming error.
func inputSchema[T any](tune func(*jsonschema.Schema)) *jsonschema.Schema {
	s, err := jsonschema.For[T](nil)
	if err != nil {
		panic(err)
	}
	tune(s)
	return s
}

func ptr[T any](v T) *T { return &v }
