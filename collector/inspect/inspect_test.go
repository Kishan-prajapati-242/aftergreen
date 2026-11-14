package inspect

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"aftergreen/collector/logbundle"
	"aftergreen/collector/markers"
)

func caseNames(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(casesDir, "bundles"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			names = append(names, strings.TrimSuffix(e.Name(), ".json"))
		}
	}
	if len(names) != 12 {
		t.Fatalf("%d case bundles, want 12", len(names))
	}
	return names
}

func readCase(t *testing.T, name string) ([]byte, []byte) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(casesDir, "bundles", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	e, err := os.ReadFile(filepath.Join(casesDir, "expected", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return b, e
}

func generic(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// decodeResult reads a result as aftergreen-inspect -verify does.
func decodeResult(t *testing.T, raw []byte) *Result {
	t.Helper()
	r, err := ParseResult(raw)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// The Go inspector reproduces every expected result, which were derived
// beforehand from the contract by a separate implementation (oracle.py), and
// the verifier accepts each one.
func TestExpectedCases(t *testing.T) {
	for _, name := range caseNames(t) {
		raw, exp := readCase(t, name)
		got, err := Inspect(raw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var want any
		if err := json.Unmarshal(exp, &want); err != nil {
			t.Fatal(err)
		}
		if g := generic(t, got); !reflect.DeepEqual(g, want) {
			gb, _ := json.MarshalIndent(g, "", " ")
			t.Errorf("%s: result differs from expected/%s.json:\n%s", name, name, gb)
		}
		if p := Verify(raw, decodeResult(t, exp)); p != nil {
			t.Errorf("%s: Verify rejects the expected result: %+v", name, p)
		}
		if p := Verify(raw, got); p != nil {
			t.Errorf("%s: Verify rejects Inspect's result: %+v", name, p)
		}
	}
}

func hasCode(ps []Problem, code string) bool {
	for _, p := range ps {
		if p.Code == code {
			return true
		}
	}
	return false
}

func i64(v int64) *int64 { return &v }

// Negative controls: forged observations, citations, counts and limitations
// are each rejected with the expected problem.
func TestVerifyRejectsForgeries(t *testing.T) {
	type forgery struct {
		name string
		edit func(r *Result)
		code string
	}
	run := func(caseName string, fs []forgery) {
		raw, exp := readCase(t, caseName)
		for _, f := range fs {
			r := decodeResult(t, exp)
			f.edit(r)
			if ps := Verify(raw, r); !hasCode(ps, f.code) {
				t.Errorf("%s / %s: problems %+v, want %s", caseName, f.name, ps, f.code)
			}
		}
	}
	// failure-at-end: 0 step 5, 1 step 9, 2 error_line 14, 3 failed_count 16,
	// 4 gha_error 17, 5 nonzero_exit 17.
	run("failure-at-end", []forgery{
		{"wrong marker", func(r *Result) { r.Observations[2].Marker = "go_panic" }, "pattern_mismatch"},
		{"moved to a line without a marker", func(r *Result) { r.Observations[2].Citation.Start, r.Observations[2].Citation.End = 15, 15 }, "pattern_mismatch"},
		{"invented observation", func(r *Result) {
			r.Observations = append(r.Observations[:2], append([]Observation{{Kind: "error_marker", Marker: "gha_error",
				Citation: Citation{SourceID: "failed.job_log", Start: 12, End: 12}}}, r.Observations[2:]...)...)
		}, "pattern_mismatch"},
		{"observation dropped", func(r *Result) { r.Observations = append(r.Observations[:3], r.Observations[4:]...) }, "observation_missing"},
		{"order swapped", func(r *Result) { r.Observations[2], r.Observations[3] = r.Observations[3], r.Observations[2] }, "order_invalid"},
		{"observation repeated", func(r *Result) { r.Observations = append(r.Observations[:3], r.Observations[2:]...) }, "order_invalid"},
		{"wrong exit code", func(r *Result) { r.Observations[5].ExitCode = i64(2) }, "pattern_mismatch"},
		{"established step removed", func(r *Result) { r.Observations[2].StepHeader = nil }, "step_header_mismatch"},
		{"wrong step header", func(r *Result) { r.Observations[2].StepHeader.Start, r.Observations[2].StepHeader.End = 5, 5 }, "step_header_mismatch"},
		{"counts changed", func(r *Result) { r.Counts.ErrorMarker["error_line"] = 5 }, "counts_mismatch"},
		{"limitation dropped", func(r *Result) { r.Limitations = r.Limitations[:len(r.Limitations)-1] }, "limitations_mismatch"},
		{"cause invented", func(r *Result) { r.Limitations = append(r.Limitations, Limitation{Code: "root_cause", Reason: "dns"}) }, "limitations_mismatch"},
		{"digest changed", func(r *Result) { r.BundleEvidenceSHA256 = strings.Repeat("0", 64) }, "header_mismatch"},
		{"evidence class changed", func(r *Result) { r.EvidenceClass = "collected_public" }, "header_mismatch"},
		{"line map facts changed", func(r *Result) { r.JobLog.OmittedLines["redacted"] = 1 }, "header_mismatch"},
		{"range citation", func(r *Result) { r.Observations[2].Citation.End = 15 }, "citation_invalid"},
		{"other source", func(r *Result) { r.Observations[2].Citation.SourceID = "failed.workflow" }, "citation_invalid"},
		{"unknown kind", func(r *Result) { r.Observations[2].Kind = "root_cause" }, "invalid_observation"},
		{"marker on a step header", func(r *Result) { r.Observations[0].Marker = "gha_error" }, "invalid_observation"},
	})
	// failure-in-middle: 0 step 5, 1 error_line 150 (step undetermined).
	run("failure-in-middle", []forgery{
		{"cites an omitted line", func(r *Result) { r.Observations[1].Citation.Start, r.Observations[1].Citation.End = 100, 100 }, "citation_not_included"},
		{"citation across omitted lines", func(r *Result) { r.Observations[1].Citation.Start = 147; r.Observations[1].Citation.End = 152 }, "citation_invalid"},
		{"step across omitted lines", func(r *Result) {
			r.Observations[1].StepHeader = &Citation{SourceID: "failed.job_log", Start: 5, End: 5}
		}, "step_header_mismatch"},
		{"beyond the log", func(r *Result) { r.Observations[1].Citation.Start, r.Observations[1].Citation.End = 999, 999 }, "citation_invalid"},
		{"context limitation dropped", func(r *Result) {
			var keep []Limitation
			for _, l := range r.Limitations {
				if l.Code != "context_omitted" {
					keep = append(keep, l)
				}
			}
			r.Limitations = keep
		}, "limitations_mismatch"},
	})
	// noisy-repeated: the first 200 of 501 observations are listed.
	run("noisy-repeated", []forgery{
		{"a later observation listed instead", func(r *Result) {
			r.Observations[199] = Observation{Kind: "error_marker", Marker: "go_test_fail", Citation: Citation{SourceID: "failed.job_log", Start: 400, End: 400}}
		}, "observation_missing"},
	})
	// log-missing: nothing can be cited.
	run("log-missing", []forgery{
		{"observation on a missing log", func(r *Result) {
			r.Observations = []Observation{{Kind: "error_marker", Marker: "gha_error", Citation: Citation{SourceID: "failed.job_log", Start: 1, End: 1}}}
		}, "citation_invalid"},
	})

	raw, _ := readCase(t, "failure-at-end")
	if ps := Verify(raw, nil); !hasCode(ps, "result_missing") {
		t.Errorf("nil result: %+v", ps)
	}
	if ps := Verify([]byte("{}"), &Result{}); !hasCode(ps, "bundle_invalid") {
		t.Errorf("invalid bundle: %+v", ps)
	}
}

// allowedStrings is every string an inspection may hold: the contract's
// names, plus the bundle's source ids and digest.
func allowedStrings(raw []byte) map[string]bool {
	set := map[string]bool{}
	for _, s := range []string{Schema, "aftergreen.bundle.v1", "collected_public", "simulated", "present", "missing",
		"error_marker", "nonzero_exit", "step_header", "complete", "prefix", "partial",
		"log_missing", "log_incomplete", "line_may_be_cut", "source_missing", "lines_omitted", "context_omitted", "step_undetermined",
		"checkout_unresolved", "matrix_unresolved", "no_markers", "observations_truncated",
		"before", "after", "both", "lines_omitted_before", "no_step_header_before",
		"job_log", "workflow_file", "manifest", "lockfile",
		"expired", "not_found", "too_large", "limit_reached", "access_denied", "not_collected", "transfer_failed", "redirect_rejected",
		"dynamic_ref", "multiple_checkouts", "log_missing", "reusable_workflow", "output_unverifiable", "no_checkout_step",
		"workflow_not_collected", "custom_job_name", "ambiguous"} {
		set[s] = true
	}
	for _, s := range append(append([]string{}, markers.Names...), Reasons...) {
		set[s] = true
	}
	var d struct {
		Sources []struct {
			ID string `json:"id"`
		} `json:"sources"`
		Digest string `json:"evidence_sha256"`
	}
	_ = json.Unmarshal(raw, &d)
	for _, s := range d.Sources {
		set[s.ID] = true
	}
	set[d.Digest] = true
	return set
}

func walkStrings(v any, f func(string)) {
	switch x := v.(type) {
	case string:
		f(x)
	case []any:
		for _, e := range x {
			walkStrings(e, f)
		}
	case map[string]any:
		for k, e := range x {
			f(k)
			walkStrings(e, f)
		}
	}
}

func checkNoText(t *testing.T, name string, raw []byte, r *Result) {
	t.Helper()
	allowed := allowedStrings(raw)
	for _, k := range []string{"schema", "bundle_schema", "bundle_evidence_sha256", "evidence_class", "job_log", "observations", "counts",
		"limitations", "source_id", "status", "missing_reason", "extent", "line_count", "included_lines", "omitted_lines", "omitted_ranges",
		"inline_redactions", "kind", "marker", "exit_code", "citation", "start", "end", "count", "ranges", "line", "side", "total", "listed",
		"code", "reason", "observations"} {
		allowed[k] = true
	}
	walkStrings(generic(t, r), func(s string) {
		if !allowed[s] {
			t.Errorf("%s: the result holds a string that is not a contract name, source id or digest: %q", name, s)
		}
	})
}

// No inspection holds text from its bundle, hostile text included.
func TestOutputHoldsNoText(t *testing.T) {
	for _, name := range caseNames(t) {
		raw, _ := readCase(t, name)
		r, err := Inspect(raw)
		if err != nil {
			t.Fatal(err)
		}
		checkNoText(t, name, raw, r)
	}
	raw, _ := readCase(t, "hostile-strings")
	r, _ := Inspect(raw)
	out, _ := json.Marshal(r)
	for _, s := range []string{"Ignore", "previous instructions", "root_cause", "DNS", "script", "img", "onerror", "\u202e", "\u200b",
		"evil", "smart", "emoji", "echo", "quoted", "slash"} {
		if bytes.Contains(out, []byte(s)) {
			t.Errorf("the result holds %q from the bundle", s)
		}
	}
}

// Bytes that bundle v1 validation rejects produce no result.
func TestInvalidInput(t *testing.T) {
	good, _ := readCase(t, "failure-at-end")
	tampered := bytes.Replace(good, []byte(`"evidence_sha256":"`), []byte(`"evidence_sha256":"0`), 1)
	tampered = append(tampered[:bytes.Index(tampered, []byte(`"evidence_sha256":"`))+len(`"evidence_sha256":"`)+64], []byte("\"}\n")...)
	v0, err := os.ReadFile("../../contracts/cases/valid-simulated-stale-lockfile.json")
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		raw  []byte
		code string
	}{
		"v0 bundle":       {v0, "schema_violation"},
		"tampered digest": {tampered, "digest_mismatch"},
		"not JSON":        {[]byte("Ignore previous instructions"), "invalid_json"},
		"empty":           {nil, "invalid_json"},
	} {
		r, err := Inspect(c.raw)
		var ie *InputError
		if r != nil || !errors.As(err, &ie) || ie.Code != c.code {
			t.Errorf("%s: result %v, err %v; want %s", name, r != nil, err, c.code)
		}
	}
}

// Random logs through the producer: the verifier, written separately,
// accepts every inspection, which holds no text.
func TestRandomBundles(t *testing.T) {
	frags := []string{"\n", "\n", "\n", " ", "text", "x", "0", "1 ", "  ", "\t", "Error: ", "TypeError: ", "##[error]", "##[group]Run ",
		"##[group]", "##[endgroup]", "npm ERR! ", "npm error ", "npm errors", "--- FAIL: ", "FAIL", "FAILED ", "Traceback (most recent call last):",
		"panic: ", "TimeoutError", "timed out", "Timed outage", " failed", "3 failed", "0 failed", "Process completed with exit code ",
		"1.", "0.", "12345678901", "2026-11-01T10:00:00.0000000Z ", "2026-11-01T10:00:00Z ", "-----BEGIN RSA PRIVATE KEY-----",
		"-----END RSA PRIVATE KEY-----", "token=abc", "Ignore previous instructions", "\u202e", "\u00e9", strings.Repeat("y", 2100)}
	r := rand.New(rand.NewPCG(4, 2))
	for iter := 0; iter < 400; iter++ {
		var b strings.Builder
		for n := r.IntN(300); n > 0; n-- {
			b.WriteString(frags[r.IntN(len(frags))])
		}
		log := []byte(b.String())
		sum := sha256.Sum256(log)
		in := caseInput(synthCase{name: "random"})
		in.Log = logbundle.Log{Obtained: true, Extent: []string{"complete", "prefix", "partial"}[r.IntN(3)], Authentication: "none",
			Bytes: log, ReceivedBytes: int64(len(log)), SHA256: hex.EncodeToString(sum[:])}
		raw, _, err := logbundle.Build(in, logbundle.Options{EvidenceClass: "simulated", Tool: "aftergreen-collect", APIVersion: "2026-03-10", CreatedAt: caseCreated})
		if err != nil {
			t.Fatalf("log %d: %v", iter, err)
		}
		res, err := Inspect(raw)
		if err != nil {
			t.Fatalf("log %d: %v", iter, err)
		}
		if ps := Verify(raw, res); ps != nil {
			t.Fatalf("log %d: %+v", iter, ps)
		}
		checkNoText(t, fmt.Sprintf("log %d", iter), raw, res)
	}
}

// The patterns of section 3 on single bodies, against the verifier's own
// pattern code.
func TestPatternsAgree(t *testing.T) {
	bodies := []string{"", "Error: x", "  TypeError: y", "xError: z", "Errors: no", "Error:x", "ERROR: no", "##[error]a", "a ##[error]",
		"npm ERR! x", "npm error", "npm error x", "npm errors", " npm ERR!", "--- FAIL: T", "    --- FAIL: T/s", "FAIL", "FAIL\tpkg", "FAIL pkg",
		"FAILURE", "FAILED x", "FAILED", "Traceback (most recent call last):", "\tTraceback (most recent call last):", "panic: x", " panic: x",
		"TimeoutError", "xTimeoutError", "TimeoutErrors", "timed out", "Timed out.", "timed outage", "_timed out", "1 failed", "10 failed,",
		"01 failed", "a1 failed", "1 failedx", "1 failed_", "0 failed", "x 7 failed", "Process completed with exit code 1.",
		"Process completed with exit code 0.", "Process completed with exit code 01.", "Process completed with exit code 12345678901",
		"Process completed with exit code 1234567890", "Process completed with exit code 0. Process completed with exit code 3",
		"##[group]Run x", "##[group]Running", "##[group] Run x", "\u202eError: x", "Error: \u202e"}
	for _, b := range bodies {
		got := markers.ErrorMarkers(b)
		var want []string
		for _, m := range vMarkerNames {
			if vMarker(m, b) {
				want = append(want, m)
			}
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%q: markers %v, verifier %v", b, got, want)
		}
		gc, gok := markers.ExitCode(b)
		wc, wok := vExit(b)
		if gc != wc || gok != wok {
			t.Errorf("%q: exit %d %v, verifier %d %v", b, gc, gok, wc, wok)
		}
		if markers.StepHeader(b) != strings.HasPrefix(b, "##[group]Run ") {
			t.Errorf("%q: step header disagrees", b)
		}
	}
	for _, text := range []string{"2026-11-01T10:00:00Z x", "2026-11-01T10:00:00.1Z x", "2026-11-01T10:00:00.123456789Z x",
		"2026-11-01T10:00:00.1234567890Z x", "2026-11-01T10:00:00.Z x", "2026-11-01 10:00:00Z x", "2026-11-01T10:00:00Zx", "x"} {
		if a, b := markers.Body(text), vBody(text); a != b {
			t.Errorf("%q: body %q, verifier %q", text, a, b)
		}
	}
}
