// Package logbundle turns one downloaded job log and its run metadata into a
// contract v1 evidence bundle (contracts/bundle-v1.md). The steps, in order:
//
//  1. Number the original lines of the received bytes (split on LF; a CR just
//     before an LF is dropped; a final LF starts no line).
//  2. Clean each line: repair malformed UTF-8, drop a leading byte-order mark
//     on line 1, remove terminal escape sequences and other control
//     characters. A line's number never changes.
//  3. Redact with rule set aftergreen.redaction.1 (redact.go): private-key
//     blocks spanning lines, and lines where removing escape sequences could
//     hide a match, are omitted as "redacted"; known secret shapes inside a
//     line are replaced by "[REDACTED:<rule>]".
//  4. Select relevant lines with context within the bundle limits
//     (select.go). Every other line is listed in an omitted range with its
//     reason.
//
// Rule-based redaction finds what its rules match. It cannot guarantee that
// a log holds no other secret.
//
// The raw log is held in memory only. Nothing in this package writes it,
// prints it, or puts it in an error.
package logbundle

import (
	"bytes"
	"strings"
	"unicode/utf8"
)

// splitLines numbers the lines of raw by contracts/bundle-v1.md section 4.
func splitLines(raw []byte) [][]byte {
	if len(raw) == 0 {
		return nil
	}
	parts := bytes.Split(raw, []byte{'\n'})
	if len(parts[len(parts)-1]) == 0 {
		parts = parts[:len(parts)-1] // a final LF starts no line
	}
	for i, p := range parts {
		if i < len(parts)-1 || bytes.HasSuffix(raw, []byte{'\n'}) {
			parts[i] = bytes.TrimSuffix(p, []byte{'\r'}) // only a CR directly before an LF
		}
	}
	return parts
}

// cleanLine repairs malformed UTF-8, drops a byte-order mark at the start of
// the first line, removes terminal escape sequences, and removes every
// remaining control character except tab (U+0000-U+001F, U+007F-U+009F).
func cleanLine(b []byte, first bool) string {
	s := strings.ToValidUTF8(string(b), "\uFFFD")
	if first {
		s = strings.TrimPrefix(s, "\uFEFF")
	}
	return dropControls(stripEscapes(s))
}

// plainLine is the line with malformed UTF-8 repaired, a first-line
// byte-order mark dropped and control characters removed, but the printable
// bytes of escape sequences kept. Redaction checks it as well as the cleaned
// text (redact.go).
func plainLine(b []byte, first bool) string {
	s := strings.ToValidUTF8(string(b), "\uFFFD")
	if first {
		s = strings.TrimPrefix(s, "\uFEFF")
	}
	return dropControls(s)
}

// stripEscapes removes ECMA-48 escape sequences: CSI (ESC [ or U+009B, with
// parameters, intermediates and a final byte), OSC (ESC ] or U+009D, to BEL
// or ST), DCS, SOS, PM and APC strings (to ST or BEL), and two-byte and
// intermediate ESC sequences. An unterminated sequence runs to the end of the
// line.
func stripEscapes(s string) string {
	if !strings.ContainsAny(s, "\x1b\u009b\u009d\u0090\u0098\u009e\u009f") {
		return s
	}
	var out strings.Builder
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case r == 0x1b && i+1 < len(rs) && rs[i+1] == '[':
			i = skipCSI(rs, i+2)
		case r == 0x9b:
			i = skipCSI(rs, i+1)
		case r == 0x1b && i+1 < len(rs) && (rs[i+1] == ']' || rs[i+1] == 'P' || rs[i+1] == 'X' || rs[i+1] == '^' || rs[i+1] == '_'):
			i = skipString(rs, i+2)
		case r == 0x9d || r == 0x90 || r == 0x98 || r == 0x9e || r == 0x9f:
			i = skipString(rs, i+1)
		case r == 0x1b:
			j := i + 1
			for j < len(rs) && rs[j] >= 0x20 && rs[j] <= 0x2f { // intermediates
				j++
			}
			if j < len(rs) && rs[j] >= 0x30 && rs[j] <= 0x7e { // final
				i = j
			} else {
				i = j - 1 // a lone ESC; the next character is kept
			}
		default:
			out.WriteRune(r)
		}
	}
	return out.String()
}

// skipCSI returns the index of the final byte of a CSI sequence whose
// parameters start at i, or the last index if it never ends.
func skipCSI(rs []rune, i int) int {
	for ; i < len(rs); i++ {
		switch r := rs[i]; {
		case r >= 0x40 && r <= 0x7e:
			return i // final byte
		case r < 0x20 || r > 0x7e:
			return i - 1 // not a CSI byte: the sequence ends before it, and it is kept
		}
		// 0x20-0x3f: parameter or intermediate byte
	}
	return len(rs) - 1
}

// skipString returns the index of the terminator (BEL, ESC \ or U+009C) of a
// control string whose body starts at i, or the last index if it never ends.
func skipString(rs []rune, i int) int {
	for ; i < len(rs); i++ {
		switch {
		case rs[i] == 0x07 || rs[i] == 0x9c:
			return i
		case rs[i] == 0x1b && i+1 < len(rs) && rs[i+1] == '\\':
			return i + 1
		}
	}
	return len(rs) - 1
}

func dropControls(s string) string {
	clean := true
	for _, r := range s {
		if isControl(r) {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var out strings.Builder
	for _, r := range s {
		if !isControl(r) {
			out.WriteRune(r)
		}
	}
	return out.String()
}

func isControl(r rune) bool {
	return (r < 0x20 && r != '\t') || r == 0x7f || (r >= 0x80 && r <= 0x9f)
}

// validText reports whether s may be a v1 line text: valid UTF-8 without a
// control character other than tab.
func validText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if isControl(r) {
			return false
		}
	}
	return true
}
