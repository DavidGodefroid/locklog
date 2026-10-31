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
	maxDuration = 16  // a duration such as 24h or 7d
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
