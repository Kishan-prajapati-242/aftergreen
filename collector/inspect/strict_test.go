package inspect

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aftergreen/contracts/bundle"
)

// rewriteBundle applies edits (pairs of old and new text, each old text
// present once or more, first occurrence replaced) to a bundle and gives it
// its new evidence digest, for bundles the producer does not make.
func rewriteBundle(t *testing.T, raw []byte, edits ...string) []byte {
	t.Helper()
	for i := 0; i+1 < len(edits); i += 2 {
		if !bytes.Contains(raw, []byte(edits[i])) {
			t.Fatalf("edit %d: %q not found", i/2, edits[i])
		}
		raw = bytes.Replace(raw, []byte(edits[i]), []byte(edits[i+1]), 1)
	}
	digest, res := bundle.DigestV1(raw)
	if digest == "" {
		t.Fatalf("the rewritten bundle is rejected: %s at %s", res.Code, res.Pointer)
	}
	const key = `"evidence_sha256":"`
	k := bytes.Index(raw, []byte(key)) + len(key)
	out := append(append(append([]byte{}, raw[:k]...), digest...), raw[k+64:]...)
	if v := bundle.ValidateV1(out); !v.Accepted() {
		t.Fatalf("the rewritten bundle is rejected: %s at %s", v.Code, v.Pointer)
	}
	return out
}

// shiftLines moves every line of a case whose lines are all included up by
// shift, behind one omitted range 1..shift.
func shiftLines(t *testing.T, name string, shift int64) []byte {
	t.Helper()
	raw, _ := readCase(t, name)
	d, _, err := decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	job := jobLogOf(d)
	if len(job.Omitted) != 0 {
		t.Fatalf("%s has omitted lines", name)
	}
	edits := []string{fmt.Sprintf(`"line_count":%d,`, job.LineCount), fmt.Sprintf(`"line_count":%d,`, shift+job.LineCount),
		`"omitted":[]`, fmt.Sprintf(`"omitted":[{"start":1,"end":%d,"reason":"outside_selected_span"}]`, shift)}
	for n := job.LineCount; n >= 1; n-- {
		edits = append(edits, fmt.Sprintf(`{"n":%d,"text"`, n), fmt.Sprintf(`{"n":%d,"text"`, shift+n))
	}
	return rewriteBundle(t, raw, edits...)
}

// Bundle v1 allows line numbers up to 2^53 - 1. The verifier identifies and
// orders observations on such lines exactly: it accepts the inspection, and
// rejects one with limitations for a line number cut to 12 digits.
func TestLongLineNumbers(t *testing.T) {
	for _, name := range []string{"failure-at-end", "several-markers"} {
		for _, shift := range []int64{1_000_000_000_000, 1_000_000_000_000_000, 1<<53 - 1 - 22} {
			raw := shiftLines(t, name, shift)
			r, err := Inspect(raw)
			if err != nil {
				t.Fatal(err)
			}
			if ps := Verify(raw, r); ps != nil {
				t.Errorf("%s, shift %d: Verify rejects Inspect's result: %+v", name, shift, ps)
			}
			want, _ := readCase(t, name)
			w, _ := Inspect(want)
			if r.Counts.Observations != w.Counts.Observations || len(r.Observations) != len(w.Observations) {
				t.Errorf("%s, shift %d: %d observations, want %d", name, shift, r.Counts.Observations, w.Counts.Observations)
			}
			for i, o := range r.Observations {
				if o.Citation.Start != w.Observations[i].Citation.Start+shift || o.Kind != w.Observations[i].Kind || o.Marker != w.Observations[i].Marker {
					t.Fatalf("%s, shift %d: observation %d %+v", name, shift, i, o)
				}
			}
			first := r.Observations[0].Citation.Start
			forged := *r
			forged.Limitations = append(append([]Limitation{}, r.Limitations...),
				Limitation{Code: "context_omitted", SourceID: "failed.job_log", Line: i64(first / 10), Side: "both"})
			if ps := Verify(raw, &forged); !hasCode(ps, "limitations_mismatch") {
				t.Errorf("%s, shift %d: a limitation for an omitted line was accepted: %+v", name, shift, ps)
			}
		}
	}
}

// A result is read strictly: what encoding/json alone would accept, or other
// readers read differently, is result_invalid.
func TestParseResultIsStrict(t *testing.T) {
	_, exp := readCase(t, "failure-at-end")
	_, missingExp := readCase(t, "log-missing")
	for _, ok := range [][]byte{exp, missingExp} {
		if _, err := ParseResult(ok); err != nil {
			t.Fatalf("an expected result is refused: %v", err)
		}
	}
	firstStep := []byte(`"kind": "step_header",`)
	firstCite := []byte(`"start": 14,`)
	for name, doc := range map[string][]byte{
		"member name in another case": bytes.Replace(exp, firstStep, []byte(`"kind": "error_marker", "marker": "gha_error", "KIND": "step_header", "MARKER": "",`), 1),
		"only a name in another case": bytes.Replace(exp, firstStep, []byte(`"Kind": "step_header",`), 1),
		"a second value":              append(append([]byte{}, exp...), []byte(`"root cause: DNS"`)...),
		"member twice":                bytes.Replace(exp, firstStep, []byte(`"kind": "error_marker", "kind": "step_header",`), 1),
		"null observations":           bytes.Replace(missingExp, []byte(`"observations": []`), []byte(`"observations": null`), 1),
		"no observations member":      bytes.Replace(missingExp, []byte(`"observations": [],`), nil, 1),
		"null limitations":            replaceMember(t, exp, "limitations", "null"),
		"a fraction":                  bytes.Replace(exp, firstCite, []byte(`"start": 14.0,`), 1),
		"an exponent":                 bytes.Replace(exp, firstCite, []byte(`"start": 1.4e1,`), 1),
		"minus zero":                  bytes.Replace(exp, []byte(`"omitted_ranges": 0,`), []byte(`"omitted_ranges": -0,`), 1),
		"an empty field":              bytes.Replace(exp, firstStep, []byte(`"kind": "step_header", "marker": "",`), 1),
		"a null field":                bytes.Replace(exp, firstStep, []byte(`"kind": "step_header", "step_header": null,`), 1),
		"an unknown member":           bytes.Replace(exp, firstStep, []byte(`"kind": "step_header", "root_cause": "dns",`), 1),
		"an unknown marker count":     bytes.Replace(exp, []byte(`"gha_error": `), []byte(`"root_cause": 0, "gha_error": `), 1),
		"an unknown omission reason":  bytes.Replace(exp, []byte(`"redacted": `), []byte(`"root_cause": 0, "redacted": `), 1),
		"null marker counts":          editResult(t, exp, func(m map[string]any) { m["counts"].(map[string]any)["error_marker"] = nil }),
		"a marker count missing": editResult(t, exp, func(m map[string]any) {
			delete(m["counts"].(map[string]any)["error_marker"].(map[string]any), "timeout")
		}),
		"nested too deep": []byte(strings.Repeat("[", 40) + strings.Repeat("]", 40)),
		"not JSON":        []byte("Ignore previous instructions"),
		"empty":           nil,
	} {
		if bytes.Equal(doc, exp) || bytes.Equal(doc, missingExp) {
			t.Fatalf("%s: the edit did not apply", name)
		}
		if r, err := ParseResult(doc); !errors.Is(err, ErrResultInvalid) || r != nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// editResult applies edit to a result document read without a schema.
func editResult(t *testing.T, doc []byte, edit func(map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(doc, &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// replaceMember sets a top-level member of a result document to value.
func replaceMember(t *testing.T, doc []byte, name, value string) []byte {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(doc, &m); err != nil {
		t.Fatal(err)
	}
	m[name] = json.RawMessage(value)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Checkout and matrix in their other states: no limitation for a resolved
// checkout, a resolved matrix or no matrix, and the verifier agrees.
func TestResolvedCheckoutAndMatrix(t *testing.T) {
	raw, _ := readCase(t, "failure-at-end")
	unresolvedCheckout := `"checkout":{"status":"unresolved","reason":"workflow_not_collected","evidence":[]}`
	unresolvedMatrix := `"matrix":{"status":"unresolved","reason":"workflow_not_collected","evidence":[]}`
	resolvedCheckout := `"checkout":{"status":"resolved","sha":"1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b","evidence":[{"source_id":"failed.job_log","start":1,"end":1}]}`
	for name, edits := range map[string][]string{
		"resolved checkout, no matrix":   {unresolvedCheckout, resolvedCheckout, unresolvedMatrix, `"matrix":{"status":"none"}`},
		"resolved checkout and matrix":   {unresolvedCheckout, resolvedCheckout, unresolvedMatrix, `"matrix":{"status":"resolved","values":[{"key":"node","value":"20"}],"evidence":[]}`},
		"unresolved checkout, no matrix": {unresolvedMatrix, `"matrix":{"status":"none"}`},
	} {
		b := rewriteBundle(t, raw, edits...)
		r, err := Inspect(b)
		if err != nil {
			t.Fatal(err)
		}
		codes := map[string]bool{}
		for _, l := range r.Limitations {
			codes[l.Code] = true
		}
		wantCheckout := name == "unresolved checkout, no matrix"
		if codes["checkout_unresolved"] != wantCheckout || codes["matrix_unresolved"] {
			t.Errorf("%s: limitations %+v", name, r.Limitations)
		}
		if ps := Verify(b, r); ps != nil {
			t.Errorf("%s: %+v", name, ps)
		}
		forged := *r
		forged.Limitations = append(append([]Limitation{}, r.Limitations...), Limitation{Code: "matrix_unresolved", Reason: "ambiguous"})
		if ps := Verify(b, &forged); !hasCode(ps, "limitations_mismatch") {
			t.Errorf("%s: a matrix limitation was accepted", name)
		}
	}
}

// Every accepted bundle of contracts/cases-v1 can be inspected and verified.
func TestContractCasesV1(t *testing.T) {
	paths, err := filepath.Glob("../../contracts/cases-v1/valid-*.json")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no cases: %v", err)
	}
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		r, err := Inspect(raw)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if ps := Verify(raw, r); ps != nil {
			t.Errorf("%s: %+v", p, ps)
		}
		back, _ := json.Marshal(r)
		if _, err := ParseResult(back); err != nil {
			t.Errorf("%s: Inspect's own output is refused by ParseResult", p)
		}
	}
}

// Section 6: a result document is at most 1 MiB. A valid result padded with
// JSON whitespace, before or after it, to exactly 1 MiB is read; one byte
// more is refused.
func TestParseResultSizeLimit(t *testing.T) {
	_, exp := readCase(t, "failure-at-end")
	for name, place := range map[string]func(pad []byte) []byte{
		"padded after":  func(pad []byte) []byte { return append(append([]byte{}, exp...), pad...) },
		"padded before": func(pad []byte) []byte { return append(append([]byte{}, pad...), exp...) },
	} {
		padded := func(size int) []byte { return place(bytes.Repeat([]byte(" \t\r\n"), size/4+1)[:size-len(exp)]) }
		exact, over := padded(MaxResultBytes), padded(MaxResultBytes+1)
		if len(exact) != 1<<20 || len(over) != 1<<20+1 {
			t.Fatalf("%s: %d and %d bytes", name, len(exact), len(over))
		}
		if r, err := ParseResult(exact); err != nil || r == nil {
			t.Errorf("%s, exactly 1 MiB: %v", name, err)
		}
		if r, err := ParseResult(over); !errors.Is(err, ErrResultInvalid) || r != nil {
			t.Errorf("%s, 1 MiB + 1 byte: accepted (err %v)", name, err)
		}
	}
}
