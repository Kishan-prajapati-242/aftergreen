package inspect

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"

	"aftergreen/collector/markers"
)

// MaxResultBytes is the size limit of a result document (section 6): 1 MiB.
const MaxResultBytes = 1 << 20

// maxResultDepth bounds the nesting of a result document; a result nests
// four levels deep.
const maxResultDepth = 32

// ErrResultInvalid means a document is not an inspection result as section
// 6 of the contract reads one. It names no text from the document.
var ErrResultInvalid = errors.New("not an inspection v0 result document")

// ParseResult reads an inspection result strictly (contracts/inspection-v0.md
// section 6). A document over MaxResultBytes is refused before it is read.
// encoding/json alone would accept what other readers read differently: it
// matches member names without regard to case, keeps the last of two equal
// names, ignores data after the first value, and reads null as an empty
// array. ParseResult refuses all of these.
func ParseResult(raw []byte) (*Result, error) {
	if len(raw) > MaxResultBytes {
		return nil, ErrResultInvalid // before any tokenizing or decoding
	}
	if !uniqueNames(raw) {
		return nil, ErrResultInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var r Result
	if err := dec.Decode(&r); err != nil {
		return nil, ErrResultInvalid
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, ErrResultInvalid // more than one value
	}
	if r.Observations == nil || r.Limitations == nil || !exactKeys(r.Counts.ErrorMarker, markers.Names) ||
		(r.JobLog.OmittedLines != nil && !exactKeys(r.JobLog.OmittedLines, Reasons)) {
		return nil, ErrResultInvalid
	}
	// The document, read without a schema (so with exact names), must equal
	// the decoded result written back: no member in another case, no null
	// or empty field that does not apply, no number in another form.
	back, err := json.Marshal(&r)
	if err != nil {
		return nil, ErrResultInvalid
	}
	a, errA := untyped(raw)
	b, errB := untyped(back)
	if errA != nil || errB != nil || !reflect.DeepEqual(a, b) {
		return nil, ErrResultInvalid
	}
	return &r, nil
}

// exactKeys reports whether m has exactly the keys names.
func exactKeys[V any](m map[string]V, names []string) bool {
	if m == nil || len(m) != len(names) {
		return false
	}
	for _, n := range names {
		if _, ok := m[n]; !ok {
			return false
		}
	}
	return true
}

func untyped(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	err := dec.Decode(&v)
	return v, err
}

// uniqueNames reports whether raw is JSON, nested at most maxResultDepth
// deep, in which no object has a member name twice.
func uniqueNames(raw []byte) bool {
	type frame struct {
		object   bool
		names    map[string]bool
		wantName bool
	}
	var stack []*frame
	dec := json.NewDecoder(bytes.NewReader(raw))
	for {
		t, err := dec.Token()
		if err == io.EOF {
			return true
		}
		if err != nil {
			return false
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if d, ok := t.(json.Delim); ok {
			switch d {
			case '{', '[':
				if len(stack) == maxResultDepth {
					return false
				}
				if top != nil && top.object {
					top.wantName = true // this value ends the member
				}
				f := &frame{object: d == '{', wantName: true}
				if f.object {
					f.names = map[string]bool{}
				}
				stack = append(stack, f)
			default:
				stack = stack[:len(stack)-1]
			}
			continue
		}
		if top == nil || !top.object {
			continue
		}
		if top.wantName {
			name, _ := t.(string)
			if top.names[name] {
				return false
			}
			top.names[name], top.wantName = true, false
		} else {
			top.wantName = true
		}
	}
}
