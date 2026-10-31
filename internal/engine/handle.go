package engine

import (
	"bytes"
	"context"
	"encoding/json"
)

// Agent methods served by the engine (IPC log.*).
const (
	MethodSearch = "log.search"
	MethodCount  = "log.count"
)

// Handle decodes the params of an agent method and runs it. A refusal is
// the agent's error (structured, no log content); err is the engine's own
// failure. Unknown fields in params are refused.
func (e *Engine) Handle(ctx context.Context, method string, params json.RawMessage) (any, *Error, error) {
	decode := func(v any) *Error {
		d := json.NewDecoder(bytes.NewReader(params))
		d.DisallowUnknownFields()
		if err := d.Decode(v); err != nil {
			return refuse(EBadQuery, "", "invalid parameters: %s", e.o.Masker.Text(err.Error()))
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
	default:
		return nil, refuse(EBadQuery, "", "unknown method"), nil
	}
	if r, ok := err.(*Error); ok {
		return nil, r, nil
	}
	return res, nil, err
}
