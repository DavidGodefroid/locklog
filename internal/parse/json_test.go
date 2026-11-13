package parse

import (
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

// decodeJSONStd is DecodeJSON as it was on encoding/json's token reader:
// the reference DecodeJSON must read alike (#150).
func decodeJSONStd(text string) (Value, error) {
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	v, err := decodeValueStd(dec, 0)
	if err != nil {
		return Value{}, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Value{}, errors.New("trailing data")
	}
	return v, nil
}

func decodeValueStd(dec *json.Decoder, depth int) (Value, error) {
	tok, err := dec.Token()
	if err != nil {
		return Value{}, err
	}
	switch t := tok.(type) {
	case nil:
		return Value{Kind: KindNull}, nil
	case bool:
		if t {
			return Value{Kind: KindBool, Str: "true"}, nil
		}
		return Value{Kind: KindBool, Str: "false"}, nil
	case json.Number:
		return Value{Kind: KindNumber, Str: string(t)}, nil
	case string:
		return Value{Kind: KindString, Str: t}, nil
	case json.Delim:
		if depth >= MaxDepth {
			return Value{}, errStructure
		}
		switch t {
		case '{':
			v := Value{Kind: KindObject, Members: []Member{}}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return Value{}, err
				}
				key, ok := kt.(string)
				if !ok {
					return Value{}, errors.New("key")
				}
				if len(key) > MaxKeyBytes {
					return Value{}, errStructure
				}
				mv, err := decodeValueStd(dec, depth+1)
				if err != nil {
					return Value{}, err
				}
				v.Members = append(v.Members, Member{Key: key, Value: mv})
			}
			if _, err := dec.Token(); err != nil {
				return Value{}, err
			}
			return v, nil
		case '[':
			v := Value{Kind: KindArray, Items: []Value{}}
			for dec.More() {
				iv, err := decodeValueStd(dec, depth+1)
				if err != nil {
					return Value{}, err
				}
				v.Items = append(v.Items, iv)
			}
			if _, err := dec.Token(); err != nil {
				return Value{}, err
			}
			return v, nil
		}
	}
	return Value{}, errors.New("token")
}

var jsonCases = []string{
	``, ` `, `{}`, ` {} `, "\t{}\r\n", `[]`, `{"a":1}`, `{"a":1,"a":2}`, `{"b":1,"a":2}`,
	`{"a":-0.5e+10,"b":0,"c":-0,"d":1E5,"e":12.25}`, `{"a":01}`, `{"a":-}`, `{"a":1.}`, `{"a":1e}`, `{"a":.5}`, `{"a":+1}`,
	`{"a":true,"b":false,"c":null}`, `{"a":tru}`, `{"a":truex}`, `{"a":nul}`, `true`, `null`, `"x"`, `12`, `1 2`, `{} {}`, `{}x`,
	`{"a":[1,[2,[3]],{"b":[]}]}`, `[1,]`, `{"a":1,}`, `{,}`, `{"a"}`, `{"a":}`, `{"a" 1}`, `{1:2}`, `[1 2]`, `{"a":1`, `[`, `{`,
	`{"a":"b\"c\\d\/e\bf\fg\nh\ri\tj"}`, `{"a":"\x"}`, `{"a":"\u00e9\u20AC"}`, `{"a":"\u00g9"}`, `{"a":"\u00e"}`,
	`{"a":"\ud83d\ude00"}`, `{"a":"\ud83d"}`, `{"a":"\ude00\ud83d"}`, `{"a":"\ud83d\u0041"}`, `{"a":"\ud83dx"}`, `{"a":"\ud83d\ud83d\ude00"}`,
	"{\"a\":\"é\"}", "{\"a\":\"\xff\"}", "{\"a\":\"a\xc3\"}", "{\"\xff\":1}", "{\"a\":\"\x01\"}", "{\"a\":\"\x7f\"}", "{\"a\":\"\\u0000\"}",
	`{"a":"unterminated}`, `{"a":"x\`, `{"` + strings.Repeat("k", MaxKeyBytes) + `":1}`, `{"` + strings.Repeat("k", MaxKeyBytes+1) + `":1}`,
	strings.Repeat("[", MaxDepth) + strings.Repeat("]", MaxDepth), strings.Repeat("[", MaxDepth+1) + strings.Repeat("]", MaxDepth+1),
	`{"ts":"2026-11-13T12:00:00.000000Z","level":"info","status":200,"msg":"order confirmed in 21ms","user":"user1@shop.example"}`,
}

func checkSameJSON(t *testing.T, in string) {
	t.Helper()
	got, err := DecodeJSON(in)
	want, werr := decodeJSONStd(in)
	if (err == nil) != (werr == nil) {
		t.Fatalf("DecodeJSON(%q): error %v, encoding/json %v", in, err, werr)
	}
	if err == nil && !reflect.DeepEqual(got, want) {
		t.Fatalf("DecodeJSON(%q) = %+v, encoding/json %+v", in, got, want)
	}
}

func TestDecodeJSONAsEncodingJSON(t *testing.T) {
	for _, in := range jsonCases {
		checkSameJSON(t, in)
	}
}

func FuzzDecodeJSON(f *testing.F) {
	for _, s := range jsonCases {
		f.Add(s)
	}
	f.Fuzz(checkSameJSON)
}

func BenchmarkDecodeJSON(b *testing.B) {
	line := `{"ts":"2026-11-13T12:00:00.000000Z","level":"info","status":200,"order":4123,"msg":"order confirmed in 21ms","user":"user123@shop.example","req":"` + strings.Repeat("x", 40) + `"}`
	b.Run("locklog", func(b *testing.B) {
		b.SetBytes(int64(len(line)))
		for b.Loop() {
			DecodeJSON(line)
		}
	})
	b.Run("encoding-json", func(b *testing.B) {
		b.SetBytes(int64(len(line)))
		for b.Loop() {
			decodeJSONStd(line)
		}
	})
}
