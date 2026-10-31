package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
)

// Agent methods served by the engine (IPC log.*).
const (
	MethodSearch  = "log.search"
	MethodCount   = "log.count"
	MethodContext = "log.context"
	MethodTrace   = "log.trace"
	MethodTail    = "log.tail"
)

// Handle decodes the params of an agent method and runs it. A refusal is
// the agent's error (structured, no log content); err is the engine's own
// failure. Unknown fields in params are refused.
func (e *Engine) Handle(ctx context.Context, method string, params json.RawMessage) (any, *Error, error) {
	decode := func(v any) *Error {
		d := json.NewDecoder(bytes.NewReader(params))
		d.DisallowUnknownFields()
		if err := d.Decode(v); err != nil {
			return decodeRefusal(err)
		}
		return nil
	}
	var (
		res any
		err error
	)
	switch method {
	case MethodSearch:
		var q Query
		if r := decode(&q); r != nil {
			return nil, r, nil
		}
		res, err = e.Search(ctx, q)
	case MethodCount:
		var q CountQuery
		if r := decode(&q); r != nil {
			return nil, r, nil
		}
		res, err = e.Count(ctx, q)
	case MethodContext:
		var q ContextQuery
		if r := decode(&q); r != nil {
			return nil, r, nil
		}
		res, err = e.Context(ctx, q)
	case MethodTrace:
		var q TraceQuery
		if r := decode(&q); r != nil {
			return nil, r, nil
		}
		res, err = e.Trace(ctx, q)
	case MethodTail:
		var q TailQuery
		if r := decode(&q); r != nil {
			return nil, r, nil
		}
		res, err = e.Tail(ctx, q)
	default:
		return nil, refuse(EBadQuery, "", "unknown method"), nil
	}
	if r, ok := err.(*Error); ok {
		return nil, r, nil
	}
	return res, nil, err
}

// decodeRefusal describes a params decode error without echoing anything
// the agent wrote: not even through the masker, whose pseudonym of a guessed
// value would tell whether that value is in the logs. Only a byte offset is
// named (a type error's field path may hold a map key the agent wrote).
func decodeRefusal(err error) *Error {
	var te *json.UnmarshalTypeError
	var se *json.SyntaxError
	switch {
	case errors.As(err, &te):
		return refuse(EBadQuery, "", "invalid parameters: a value of the wrong type at byte %d", te.Offset)
	case errors.As(err, &se):
		return refuse(EBadQuery, "", "invalid parameters: malformed JSON at byte %d", se.Offset)
	}
	return refuse(EBadQuery, "", "invalid parameters: an unknown field, or a value that does not parse (see the tool's schema)")
}
