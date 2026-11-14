package logbundle

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func auditOpt() Options {
	o := testOpt
	o.Audit = true
	return o
}

func pattern(t *testing.T, a *Audit, name string) PatternAudit {
	t.Helper()
	if a == nil {
		t.Fatal("no audit")
	}
	for _, p := range a.Patterns {
		if p.Lines != p.Included+p.HiddenByInlineRedaction+omittedTotal(p) {
			t.Errorf("%s: %d lines, but %d included, %d hidden and %d omitted", p.Pattern, p.Lines, p.Included, p.HiddenByInlineRedaction, omittedTotal(p))
		}
	}
	for _, p := range a.Patterns {
		if p.Pattern == name {
			return p
		}
	}
	t.Fatalf("no pattern %s", name)
	return PatternAudit{}
}

func omittedTotal(p PatternAudit) int {
	t := 0
	for _, n := range p.Omitted {
		t += n
	}
	return t
}

func withBlank(n int, set map[int]string) []string {
	lines := make([]string, n)
	for i := range lines {
		lines[i] = fmt.Sprintf("  build output %d", i+1)
	}
	for k, v := range set {
		lines[k-1] = v
	}
	return lines
}

// Failures at the start, in the middle and at the end are all included.
func TestAuditCoversFailuresAnywhere(t *testing.T) {
	log := withBlank(3000, map[int]string{2: "Error: could not start", 1500: "--- FAIL: TestMiddle (0.01s)",
		3000: "##[error]Process completed with exit code 1."})
	_, sum, _ := mustBuild(t, logInput(joinLines(log)), auditOpt())
	a := sum.Audit
	if a.Schema != AuditSchema || a.Scope != AuditScope || a.LineCount != 3000 {
		t.Fatalf("audit header %+v", a)
	}
	for name, want := range map[string]int{"error_line": 1, "go_test_fail": 1, "gha_error": 1, "nonzero_exit": 1} {
		if p := pattern(t, a, name); p.Lines != want || p.Included != want || omittedTotal(p) != 0 {
			t.Errorf("%s: %+v", name, p)
		}
	}
	if p := pattern(t, a, "error_line"); fmt.Sprint(p.IncludedLines) != "[2]" || p.ListsTruncated {
		t.Errorf("error_line lines %v", p.IncludedLines)
	}
}

// Noisy repeated failures: the line limit cuts most of them, and the counts
// and capped lists say so.
func TestAuditNoisyRepeatedFailures(t *testing.T) {
	log := make([]string, 0, 1001)
	for i := 0; i < 1000; i++ {
		log = append(log, "--- FAIL: TestFlaky (0.00s)")
	}
	log = append(log, "##[error]Process completed with exit code 1.")
	_, sum, _ := mustBuild(t, logInput(joinLines(log)), auditOpt())
	p := pattern(t, sum.Audit, "go_test_fail")
	if p.Lines != 1000 || p.Included != 499 || p.Omitted["line_limit"] != 501 || omittedTotal(p) != 501 {
		t.Fatalf("%+v", p)
	}
	if len(p.IncludedLines) != 20 || p.IncludedLines[0] != 502 || len(p.OmittedLines) != 20 || p.OmittedLines[0] != (AuditedOmitted{1, "line_limit"}) || !p.ListsTruncated {
		t.Errorf("lists %v %v truncated %v", p.IncludedLines, p.OmittedLines, p.ListsTruncated)
	}
}

// Markers in an over-long line or a withheld key block cannot be included,
// and the audit counts them under those reasons.
func TestAuditLongAndRedactedLines(t *testing.T) {
	log := []string{"##[group]Run deploy", "Error: " + strings.Repeat("y", 3000), "-----BEGIN RSA PRIVATE KEY-----",
		"Error: in a key block", "-----END RSA PRIVATE KEY-----", "##[error]deploy failed"}
	_, sum, _ := mustBuild(t, logInput(joinLines(log)), auditOpt())
	if p := pattern(t, sum.Audit, "error_line"); p.Lines != 2 || p.Included != 0 || p.Omitted["line_too_long"] != 1 || p.Omitted["redacted"] != 1 {
		t.Errorf("error_line %+v", p)
	}
	if p := pattern(t, sum.Audit, "gha_error"); p.Included != 1 || fmt.Sprint(p.IncludedLines) != "[6]" {
		t.Errorf("gha_error %+v", p)
	}
	if p := pattern(t, sum.Audit, "step_header"); p.Included != 1 {
		t.Errorf("step_header %+v", p)
	}
}

// Every line is classified before redaction, so the totals do not depend on
// the selection. An included line whose match inline redaction removed is
// counted apart from included lines.
func TestAuditCountsBeforeRedaction(t *testing.T) {
	hidden := `api_key: "request timed out"`
	_, sum, _ := mustBuild(t, logInput(joinLines(withBlank(3000, map[int]string{2990: hidden}))), auditOpt())
	if p := pattern(t, sum.Audit, "timeout"); p.Lines != 1 || p.Included != 0 || p.HiddenByInlineRedaction != 1 || omittedTotal(p) != 0 {
		t.Errorf("included: %+v", p)
	}
	_, sum, _ = mustBuild(t, logInput(joinLines(withBlank(3000, map[int]string{1500: hidden}))), auditOpt())
	if p := pattern(t, sum.Audit, "timeout"); p.Lines != 1 || p.Included != 0 || p.HiddenByInlineRedaction != 0 || p.Omitted["outside_selected_span"] != 1 {
		t.Errorf("omitted: %+v", p)
	}
}

// An over-long line is never a selection signal itself: far from other
// signals and from the first and last lines, it is outside the selection.
func TestAuditLongLineFarFromSignals(t *testing.T) {
	log := withBlank(3000, map[int]string{1500: "Error: " + strings.Repeat("y", 3000)})
	_, sum, _ := mustBuild(t, logInput(joinLines(log)), auditOpt())
	if p := pattern(t, sum.Audit, "error_line"); p.Lines != 1 || p.Omitted["outside_selected_span"] != 1 {
		t.Errorf("%+v", p)
	}
}

// A match that exists only after redaction is not counted: here the token
// rule stops at its 251-character limit, so its placeholder ends right
// before "1 failed".
func TestAuditIgnoresMatchesMadeByRedaction(t *testing.T) {
	log := withBlank(50, map[int]string{50: "ghp_" + strings.Repeat("A", 251) + "1 failed"})
	raw, sum, _ := mustBuild(t, logInput(joinLines(log)), auditOpt())
	if p := pattern(t, sum.Audit, "failed_count"); p.Lines != 0 {
		t.Errorf("%+v", p)
	}
	if !strings.Contains(string(raw), "]1 failed") {
		t.Error("the bundle text does not show the match made by redaction")
	}
}

func TestAuditNoMarker(t *testing.T) {
	_, sum, _ := mustBuild(t, logInput(joinLines(withBlank(400, nil))), auditOpt())
	for _, p := range sum.Audit.Patterns {
		if p.Lines != 0 {
			t.Errorf("%s matched %d lines", p.Pattern, p.Lines)
		}
	}
}

// Regression for a selection miss the audit showed on a synthetic log: npm
// 10 and later write errors as "npm error", which was not a selection
// signal, so such a line far from other signals was omitted.
func TestAuditNpmErrorIsSelected(t *testing.T) {
	log := withBlank(2000, map[int]string{1000: "npm error code ERESOLVE", 2000: "##[error]Process completed with exit code 1."})
	_, sum, _ := mustBuild(t, logInput(joinLines(log)), auditOpt())
	if p := pattern(t, sum.Audit, "npm_error"); p.Lines != 1 || p.Included != 1 {
		t.Errorf("npm_error %+v", p)
	}
}

// Auditing a saved bundle against its own bytes gives the producer's own
// audit; other bytes are refused.
func TestAuditBundle(t *testing.T) {
	logs := [][]string{
		withBlank(3000, map[int]string{2: "Error: x", 1500: "FAILED t::x - y", 3000: "##[error]Process completed with exit code 1."}),
		{"##[group]Run deploy", "Error: " + strings.Repeat("y", 3000), "-----BEGIN RSA PRIVATE KEY-----", "Error: k", "-----END RSA PRIVATE KEY-----", "##[error]x"},
		withBlank(50, nil),
		withBlank(3000, map[int]string{1500: `api_key: "request timed out"`, 2990: `token = "build timed out"`}),
	}
	for i, l := range logs {
		raw := joinLines(l)
		bundleRaw, sum, _ := mustBuild(t, logInput(raw), auditOpt())
		a, err := AuditBundle(raw, bundleRaw)
		if err != nil || a.Scope != SavedAuditScope || sum.Audit.Scope != AuditScope || a.LineCount != sum.Audit.LineCount ||
			!reflect.DeepEqual(a.Patterns, sum.Audit.Patterns) {
			t.Errorf("log %d: AuditBundle %v differs from the build's audit", i, err)
		}
		other := append([]byte("x"), raw...)
		if _, err := AuditBundle(other, bundleRaw); !errors.Is(err, ErrLogMismatch) {
			t.Errorf("log %d: other bytes: %v", i, err)
		}
		// Same length and line count, one byte different: only the hash differs.
		flipped := append([]byte{}, raw...)
		if flipped[0] == 'a' {
			flipped[0] = 'b'
		} else {
			flipped[0] = 'a'
		}
		if _, err := AuditBundle(flipped, bundleRaw); !errors.Is(err, ErrLogMismatch) {
			t.Errorf("log %d: same-length other bytes: %v", i, err)
		}
		pattern(t, a, "timeout") // checks that every pattern's counts add up
		if same, err := SameSelection(bundleRaw, bundleRaw); !same || err != nil {
			t.Errorf("log %d: SameSelection with itself %v %v", i, same, err)
		}
	}
	a, _, _ := mustBuild(t, logInput(joinLines(logs[0])), testOpt)
	b, _, _ := mustBuild(t, logInput(joinLines(logs[2])), testOpt)
	if same, err := SameSelection(a, b); same || err != nil {
		t.Errorf("different logs: %v %v", same, err)
	}
	if _, err := AuditBundle(nil, []byte("{}")); err == nil {
		t.Error("an invalid bundle was audited")
	}
	in := logInput(nil)
	in.Log = Log{MissingReason: "access_denied", Authentication: "none"}
	missing, _, _ := mustBuild(t, in, testOpt)
	if _, err := AuditBundle(nil, missing); !errors.Is(err, ErrSavedLogMissing) {
		t.Errorf("a bundle without a job log: %v", err)
	}
}

// The audit is opt-in, and holds no text.
func TestAuditIsOptInAndHoldsNoText(t *testing.T) {
	_, sum, _ := mustBuild(t, logInput(secretLog()), testOpt)
	if sum.Audit != nil {
		t.Error("an audit without Options.Audit")
	}
	_, sum, _ = mustBuild(t, logInput(secretLog()), auditOpt())
	for _, p := range sum.Audit.Patterns {
		for _, o := range p.OmittedLines {
			if o.Line < 1 || o.Line > sum.Audit.LineCount {
				t.Errorf("%s: line %d", p.Pattern, o.Line)
			}
		}
	}
	if l := leaked([]byte(fmt.Sprintf("%+v", sum.Audit))); len(l) > 0 {
		t.Errorf("the audit holds %q", l)
	}
}
