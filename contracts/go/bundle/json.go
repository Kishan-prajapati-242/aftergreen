package bundle

import (
	"fmt"
	"strconv"
	"unicode/utf8"
)

// The strict JSON profile of contracts/bundle-v0.md section 1. encoding/json
// is not used for bundles because it silently accepts duplicate member names,
// matches names case-insensitively, replaces malformed text with U+FFFD and
// converts numbers; the contract rejects each of those.

type kind uint8

const (
	kindObject kind = iota + 1
	kindArray
	kindString
	kindNumber
	kindBool
	kindNull
)

func (k kind) String() string {
	switch k {
	case kindObject:
		return "object"
	case kindArray:
		return "array"
	case kindString:
		return "string"
	case kindNumber:
		return "number"
	case kindBool:
		return "boolean"
	default:
		return "null"
	}
}

type member struct {
	name  string
	value *value
}

// value is a parsed JSON value. Object members keep document order.
type value struct {
	kind    kind
	str     string   // kindString: unescaped UTF-8
	num     string   // kindNumber: canonical decimal literal
	members []member // kindObject
	items   []*value // kindArray
}

// failure is a contract violation: a stable code, a JSON Pointer and an
// informational message.
type failure struct {
	code    string
	pointer string
	detail  string
}

func failAt(code, pointer, format string, args ...any) *failure {
	return &failure{code: code, pointer: pointer, detail: fmt.Sprintf(format, args...)}
}

type parser struct {
	data  []byte
	pos   int
	depth int
}

// parseStrict parses exactly one JSON value. The caller has already checked
// the size limit and that data is well-formed UTF-8.
func parseStrict(data []byte) (*value, *failure) {
	p := &parser{data: data}
	p.skipSpace()
	v, f := p.parseValue()
	if f != nil {
		return nil, f
	}
	p.skipSpace()
	if p.pos != len(p.data) {
		return nil, p.syntax("unexpected data after the top-level value")
	}
	return v, nil
}

func (p *parser) syntax(msg string) *failure {
	return failAt(CodeInvalidJSON, "", "%s at byte %d", msg, p.pos)
}

// peek returns the current byte, or 0 at the end of input. A literal 0 byte
// is never valid where peek is used, so the two cases fail the same way.
func (p *parser) peek() byte {
	if p.pos < len(p.data) {
		return p.data[p.pos]
	}
	return 0
}

func (p *parser) skipSpace() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *parser) parseValue() (*value, *failure) {
	if p.pos >= len(p.data) {
		return nil, p.syntax("unexpected end of input")
	}
	switch c := p.data[p.pos]; {
	case c == '{':
		return p.parseObject()
	case c == '[':
		return p.parseArray()
	case c == '"':
		s, f := p.parseString()
		if f != nil {
			return nil, f
		}
		return &value{kind: kindString, str: s}, nil
	case c == '-' || (c >= '0' && c <= '9'):
		return p.parseNumber()
	case c == 't':
		return p.parseLiteral("true", kindBool)
	case c == 'f':
		return p.parseLiteral("false", kindBool)
	case c == 'n':
		return p.parseLiteral("null", kindNull)
	default:
		return nil, p.syntax("unexpected character")
	}
}

func (p *parser) enter() *failure {
	p.depth++
	if p.depth > MaxDepth {
		return failAt(CodeNestingTooDeep, "", "more than %d nested containers at byte %d", MaxDepth, p.pos)
	}
	return nil
}

func (p *parser) parseObject() (*value, *failure) {
	if f := p.enter(); f != nil {
		return nil, f
	}
	p.pos++ // '{'
	v := &value{kind: kindObject}
	p.skipSpace()
	if p.peek() == '}' {
		p.pos++
		p.depth--
		return v, nil
	}
	seen := make(map[string]struct{})
	for {
		p.skipSpace()
		if p.peek() != '"' {
			return nil, p.syntax("expected a member name")
		}
		name, f := p.parseString()
		if f != nil {
			return nil, f
		}
		if _, dup := seen[name]; dup {
			return nil, failAt(CodeDuplicateKey, "", "member name %q repeated at byte %d", name, p.pos)
		}
		seen[name] = struct{}{}
		p.skipSpace()
		if p.peek() != ':' {
			return nil, p.syntax("expected ':'")
		}
		p.pos++
		p.skipSpace()
		item, f := p.parseValue()
		if f != nil {
			return nil, f
		}
		v.members = append(v.members, member{name: name, value: item})
		p.skipSpace()
		switch p.peek() {
		case ',':
			p.pos++
		case '}':
			p.pos++
			p.depth--
			return v, nil
		default:
			return nil, p.syntax("expected ',' or '}'")
		}
	}
}

func (p *parser) parseArray() (*value, *failure) {
	if f := p.enter(); f != nil {
		return nil, f
	}
	p.pos++ // '['
	v := &value{kind: kindArray}
	p.skipSpace()
	if p.peek() == ']' {
		p.pos++
		p.depth--
		return v, nil
	}
	for {
		p.skipSpace()
		item, f := p.parseValue()
		if f != nil {
			return nil, f
		}
		v.items = append(v.items, item)
		p.skipSpace()
		switch p.peek() {
		case ',':
			p.pos++
		case ']':
			p.pos++
			p.depth--
			return v, nil
		default:
			return nil, p.syntax("expected ',' or ']'")
		}
	}
}

func (p *parser) parseString() (string, *failure) {
	p.pos++ // opening quote
	var out []byte
	for {
		if p.pos >= len(p.data) {
			return "", p.syntax("unterminated string")
		}
		c := p.data[p.pos]
		switch {
		case c == '"':
			p.pos++
			return string(out), nil
		case c == '\\':
			p.pos++
			if p.pos >= len(p.data) {
				return "", p.syntax("unterminated escape")
			}
			e := p.data[p.pos]
			p.pos++
			switch e {
			case '"', '\\', '/':
				out = append(out, e)
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'u':
				r, f := p.hex4()
				if f != nil {
					return "", f
				}
				switch {
				case r >= 0xDC00 && r <= 0xDFFF:
					return "", failAt(CodeInvalidUTF8, "", "unpaired low surrogate escape before byte %d", p.pos)
				case r >= 0xD800 && r <= 0xDBFF:
					if p.pos+1 >= len(p.data) || p.data[p.pos] != '\\' || p.data[p.pos+1] != 'u' {
						return "", failAt(CodeInvalidUTF8, "", "unpaired high surrogate escape before byte %d", p.pos)
					}
					p.pos += 2
					lo, f := p.hex4()
					if f != nil {
						return "", f
					}
					if lo < 0xDC00 || lo > 0xDFFF {
						return "", failAt(CodeInvalidUTF8, "", "unpaired high surrogate escape before byte %d", p.pos)
					}
					r = 0x10000 + (r-0xD800)<<10 + (lo - 0xDC00)
				}
				out = utf8.AppendRune(out, rune(r))
			default:
				return "", p.syntax("invalid escape")
			}
		case c < 0x20:
			return "", p.syntax("unescaped control character in string")
		default:
			out = append(out, c)
			p.pos++
		}
	}
}

func (p *parser) hex4() (uint32, *failure) {
	if p.pos+4 > len(p.data) {
		return 0, p.syntax("truncated \\u escape")
	}
	var r uint32
	for i := 0; i < 4; i++ {
		c := p.data[p.pos+i]
		var d byte
		switch {
		case c >= '0' && c <= '9':
			d = c - '0'
		case c >= 'a' && c <= 'f':
			d = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			d = c - 'A' + 10
		default:
			return 0, p.syntax("invalid \\u escape")
		}
		r = r<<4 | uint32(d)
	}
	p.pos += 4
	return r, nil
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// parseNumber reads one RFC 8259 number. A grammar error is invalid_json; a
// well-formed number outside the contract's integer profile is invalid_number.
func (p *parser) parseNumber() (*value, *failure) {
	start := p.pos
	if p.peek() == '-' {
		p.pos++
	}
	switch c := p.peek(); {
	case c == '0':
		p.pos++
	case c >= '1' && c <= '9':
		for isDigit(p.peek()) {
			p.pos++
		}
	default:
		return nil, p.syntax("invalid number")
	}
	if p.peek() == '.' {
		p.pos++
		if !isDigit(p.peek()) {
			return nil, p.syntax("invalid number")
		}
		for isDigit(p.peek()) {
			p.pos++
		}
	}
	if c := p.peek(); c == 'e' || c == 'E' {
		p.pos++
		if c := p.peek(); c == '+' || c == '-' {
			p.pos++
		}
		if !isDigit(p.peek()) {
			return nil, p.syntax("invalid number")
		}
		for isDigit(p.peek()) {
			p.pos++
		}
	}
	lit := string(p.data[start:p.pos])
	if !isCanonicalSafeInteger(lit) {
		return nil, failAt(CodeInvalidNumber, "", "number %s is not a non-negative integer of at most %d", lit, MaxSafeInteger)
	}
	return &value{kind: kindNumber, num: lit}, nil
}

func isCanonicalSafeInteger(lit string) bool {
	if lit == "" || len(lit) > 16 {
		return false
	}
	if lit[0] == '0' {
		return lit == "0"
	}
	for i := 0; i < len(lit); i++ {
		if !isDigit(lit[i]) {
			return false
		}
	}
	n, err := strconv.ParseUint(lit, 10, 64)
	return err == nil && n <= MaxSafeInteger
}

func (p *parser) parseLiteral(word string, k kind) (*value, *failure) {
	if len(p.data)-p.pos < len(word) || string(p.data[p.pos:p.pos+len(word)]) != word {
		return nil, p.syntax("invalid literal")
	}
	p.pos += len(word)
	return &value{kind: k}, nil
}
