package logbundle

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// RulesID names the redaction rule set below in a bundle's redaction.rules.
const RulesID = "aftergreen.redaction.1"

// Rule set aftergreen.redaction.1. Rules run on cleaned line text, in order.
// A replacement keeps the line, and its number, and writes
// "[REDACTED:<rule>]" in place of what matched.
//
// Multi-line rule:
//   - private-key-block: from a line where a "-----BEGIN ... PRIVATE KEY-----"
//     (or "... PRIVATE KEY BLOCK-----") marker has no END marker after it on
//     the same line, through the next line holding an END marker, or to the
//     end of the log. Those lines are omitted with reason "redacted".
//     Markers are looked for in the cleaned text and in the text with only
//     control characters removed (escape sequences' printable bytes kept).
//
// Other readings: a line is also read with the printable characters of its
// escape sequences kept, and with \" read as " and \' as ' (strings logged
// with backslash escapes, such as {\"password\":\"x\"}). When such a
// reading differs from the cleaned text and matches any inline rule, the
// whole line is omitted with reason "redacted": removing characters can hide
// a match's context (a malformed escape sequence can swallow the start of
// "password="), so the cleaned text's matches cannot be trusted for that
// line. A reading over 16 KiB is not scanned, and the line is withheld. Every
// rule match in any reading of a line is therefore replaced or withheld.
//
// Inline rules:
//   - private-key: a BEGIN ... PRIVATE KEY marker and the rest of the line, or
//     up to its END marker.
//   - github-token: gh[pousr]_ and github_pat_ tokens.
//   - authorization: the credential after "Authorization", a separator
//     (":", "=", "=>" or ":=") and a scheme (Bearer, token, Basic or Digest),
//     and after any "Bearer ". The scheme is kept.
//   - url-userinfo: user and password in scheme://user:password@host.
//   - url-query: the whole query string of an http or https URL, which is
//     where signed URLs carry their signatures.
//   - aws-key-id, slack-token, npm-token, jwt: those token shapes.
//   - assignment: the value assigned to a name containing password, passwd,
//     pwd, secret, token, apikey/api_key/api-key, accesskey, privatekey or
//     clientsecret, after ":", "=", "=>" or ":=". A value with no letter or
//     digit (GitHub's "***" mask, a YAML "|") is left alone. When another
//     assignment starts inside the replaced value and ends after it, the
//     replacement runs on to its end ("token: password: x" loses
//     "password: x").
//   - email: e-mail addresses.
//
// These rules find what they match and nothing else. They cannot recognize
// a secret with no known shape, so a sanitized log can still hold one.

var (
	keyBeginRE = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----`)
	keyEndRE   = regexp.MustCompile(`-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----`)
)

type inlineRule struct {
	name string
	re   *regexp.Regexp
	// keep is the number of leading capture groups kept before the
	// placeholder (0 replaces the whole match).
	keep int
	// suffix is written after the placeholder, for a delimiter the match
	// consumed.
	suffix string
	// skip reports a value that is left as it is.
	skip func(value string) bool
	// extend, if set, returns where the replacement ends, at or after the
	// end of the match.
	extend func(s string, valueAt, end int) int
}

// secretNames are the name parts the assignment rule looks for.
const secretNames = `password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret`

// separator is ":", "=", "=>" or ":=", with optional spaces.
const separator = `\s*(?:=>|:=|[:=])\s*`

var assignmentRE = regexp.MustCompile(`(?i)(\b[A-Za-z0-9_.-]*(?:` + secretNames + `)[A-Za-z0-9_.-]*["']?` + separator + `)("[^"]*"|'[^']*'|[^\s,;'"]+)`)

// chainEnd extends an assignment while another one starts inside the text
// replaced so far and ends after it: "token: password: x",
// ":token=>:token=>\"x\"" and "password= 'password' => 'x'" all lose x.
// It never stops short of the first value, so a secret that merely looks
// like a name is still replaced. After 32 steps it replaces the rest of the
// line.
func chainEnd(s string, valueAt, end int) int {
	at := valueAt
	for steps := 0; ; steps++ {
		if steps == 32 {
			return len(s)
		}
		m := assignmentRE.FindStringSubmatchIndex(s[at:])
		if m == nil || at+m[0] >= end {
			return end
		}
		if e := at + m[1]; e > end {
			end, at = e, at+m[3]
			continue
		}
		_, size := utf8.DecodeRuneInString(s[at+m[0]:])
		at += m[0] + size // contained in what is replaced already: look further
	}
}

var inlineRules = []inlineRule{
	{name: "private-key", re: regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|$)`)},
	{name: "github-token", re: regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,251}|github_pat_[A-Za-z0-9_]{22,244})`)},
	{name: "authorization", re: regexp.MustCompile(`(?i)(\bauthorization["']?` + separator + `["']?(?:bearer|token|basic|digest)\s+)[^\s"',;]+`), keep: 1},
	{name: "authorization", re: regexp.MustCompile(`(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]{12,}`), keep: 1},
	{name: "url-userinfo", re: regexp.MustCompile(`(?i)(\b[a-z][a-z0-9+.-]*://)[^\s/@'"<>]+@`), keep: 1, suffix: "@"},
	{name: "url-query", re: regexp.MustCompile(`(?i)(\bhttps?://[^\s?#'"<>]+\?)[^\s#'"<>]+`), keep: 1},
	{name: "aws-key-id", re: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{name: "slack-token", re: regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}`)},
	{name: "npm-token", re: regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`)},
	{name: "jwt", re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)},
	{name: "assignment", re: assignmentRE, keep: 1, extend: chainEnd,
		skip: func(v string) bool {
			v = strings.Trim(v, `"'`)
			// No letter or digit: GitHub's "***" mask, a YAML "|", or a stray
			// ">" are not values, so they get no marker.
			return !strings.ContainsFunc(v, func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }) ||
				strings.HasPrefix(v, "[REDACTED:")
		}},
	{name: "email", re: regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b`)},
}

// RuleNames lists the inline rules in order, for reports.
func RuleNames() []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range inlineRules {
		if !seen[r.name] {
			seen[r.name] = true
			out = append(out, r.name)
		}
	}
	return out
}

// redactLine applies the inline rules and returns the new text and the
// number of replacements per rule. After a replacement the search goes on
// after it; after a match that is left alone, from that match's value, which
// may hold the secret.
func redactLine(s string) (string, map[string]int) {
	var counts map[string]int
	for _, rule := range inlineRules {
		var out strings.Builder
		done, pos := 0, 0 // s[:done] is written out; the search resumes at pos
		for pos < len(s) {
			m := rule.re.FindStringSubmatchIndex(s[pos:])
			if m == nil {
				break
			}
			start, end, valueAt := pos+m[0], pos+m[1], pos+m[0]
			if rule.keep > 0 {
				valueAt = pos + m[2*rule.keep+1]
			}
			if value := s[valueAt:end]; strings.HasPrefix(value, "[REDACTED:") || (rule.skip != nil && rule.skip(value)) {
				_, size := utf8.DecodeRuneInString(s[start:])
				pos = max(valueAt, start+size) // already replaced, or not a secret
				continue
			}
			if rule.extend != nil {
				end = rule.extend(s, valueAt, end)
			}
			out.WriteString(s[done:valueAt])
			out.WriteString("[REDACTED:" + rule.name + "]" + rule.suffix)
			done, pos = end, end
			if counts == nil {
				counts = map[string]int{}
			}
			counts[rule.name]++
		}
		if done > 0 {
			out.WriteString(s[done:])
			s = out.String()
		}
	}
	return s, counts
}

// hidden reports whether another reading of a line could hold a rule match
// that its cleaned text does not show. plain is the line with the printable
// characters of its escape sequences kept.
func hidden(cleaned, plain string) bool {
	seen := map[string]bool{cleaned: true}
	for _, v := range []string{plain, unescapeQuotes(cleaned), unescapeQuotes(plain)} {
		if seen[v] {
			continue
		}
		seen[v] = true
		if len(v) > maxPlainBytes {
			return true // not scanned: withheld
		}
		if _, counts := redactLine(v); len(counts) > 0 {
			return true
		}
	}
	return false
}

// unescapeQuotes reads \" as " and \' as '.
func unescapeQuotes(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	return strings.NewReplacer(`\"`, `"`, `\'`, `'`).Replace(s)
}

const maxPlainBytes = 16 << 10

// keyBlocks marks the lines of multi-line private-key blocks: a line that
// starts inside a key, or ends inside one after walking its BEGIN and END
// markers in order. A line whose keys all begin and end on it is left to the
// inline rule.
func keyBlocks(texts []string) []bool {
	in := make([]bool, len(texts))
	open := false
	for i, t := range texts {
		was := open
		for {
			re := keyBeginRE
			if open {
				re = keyEndRE
			}
			loc := re.FindStringIndex(t)
			if loc == nil {
				break
			}
			open = !open
			t = t[loc[1]:]
		}
		in[i] = was || open
	}
	return in
}
