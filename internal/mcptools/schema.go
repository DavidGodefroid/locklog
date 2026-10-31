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
	maxChange   = 2000 // a change request
	maxRegex    = 256
	maxTop      = 100 // engine.MaxTop
	maxDuration = 16  // a duration such as 24h or 168h
	maxAround   = 50  // engine.MaxAround
	maxRef      = 4096
)

var (
	searchSchema = inputSchema[QueryIn](func(s *jsonschema.Schema) {
		tuneRange(s)
		s.Properties["limit"].Minimum, s.Properties["limit"].Maximum = ptr(1.0), ptr(float64(maxLimit))
	})
	countSchema    = inputSchema[CountIn](tuneRange)
	patternsSchema = inputSchema[PatternsIn](func(s *jsonschema.Schema) {
		tuneRange(s)
		s.Properties["top"].Minimum, s.Properties["top"].Maximum = ptr(1.0), ptr(float64(maxTop))
		s.Properties["baseline"].MaxLength = ptr(maxDuration)
	})
	contextSchema = inputSchema[ContextIn](func(s *jsonschema.Schema) {
		s.Properties["ref"].MinLength, s.Properties["ref"].MaxLength = ptr(1), ptr(maxRef)
		for _, k := range []string{"before", "after"} {
			s.Properties[k].Minimum, s.Properties[k].Maximum = ptr(0.0), ptr(float64(maxAround))
		}
	})
	traceSchema = inputSchema[TraceIn](func(s *jsonschema.Schema) {
		s.Properties["id"].MinLength, s.Properties["id"].MaxLength = ptr(1), ptr(maxValue)
		s.Properties["limit"].Minimum, s.Properties["limit"].Maximum = ptr(1.0), ptr(float64(maxLimit))
	})
	tailSchema = inputSchema[TailIn](func(s *jsonschema.Schema) {
		tuneRange(s)
		s.Properties["duration"].MaxLength = ptr(maxDuration)
		s.Properties["max"].Minimum, s.Properties["max"].Maximum = ptr(1.0), ptr(float64(maxLimit))
	})
	piiAddSchema = inputSchema[PIIAddIn](func(s *jsonschema.Schema) {
		s.Properties["pattern"].MinLength, s.Properties["pattern"].MaxLength = ptr(1), ptr(maxPattern)
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
