package inspect

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"aftergreen/contracts/bundle"
)

// Problem is one verification failure (contracts/inspection-v0.md section
// 6). Observation is the index of the observation it concerns, or -1.
type Problem struct {
	Code        string `json:"code"`
	Observation int    `json:"observation"`
	Detail      string `json:"detail"`
}

// Verify checks r against raw without trusting it. It shares only bundle
// decoding with Inspect: patterns, step attribution, counts and limitations
// are re-derived here by separate code, written character by character
// rather than with the markers package's regular expressions.
func Verify(raw []byte, r *Result) []Problem {
	if r == nil {
		return []Problem{{Code: "result_missing", Observation: -1, Detail: "no result to verify"}}
	}
	d, digest, err := decode(raw)
	if err != nil {
		// The validator's code only: its pointer can hold member names from
		// the file, and a Problem holds no text from the input.
		detail := "the bundle could not be decoded"
		var ie *InputError
		if errors.As(err, &ie) {
			detail = "not an accepted bundle v1: " + ie.Code
		}
		return []Problem{{Code: "bundle_invalid", Observation: -1, Detail: detail}}
	}
	var ps []Problem
	add := func(code string, i int, format string, args ...any) {
		ps = append(ps, Problem{Code: code, Observation: i, Detail: fmt.Sprintf(format, args...)})
	}
	job := jobLogOf(d)
	f := readLog(job)

	if r.Schema != Schema || r.BundleSchema != bundle.SchemaVersionV1 || r.BundleEvidenceSHA256 != digest || r.EvidenceClass != d.EvidenceClass {
		add("header_mismatch", -1, "schema, bundle schema, evidence digest or evidence class differ from the bundle")
	}
	if !reflect.DeepEqual(r.JobLog, f.jobLog()) {
		add("header_mismatch", -1, "job_log differs from the bundle")
	}

	// Each listed observation, on its own.
	for i, o := range r.Observations {
		switch {
		case o.Kind == "error_marker" && vMarkerKnown(o.Marker) && o.ExitCode == nil:
		case o.Kind == "nonzero_exit" && o.Marker == "" && o.ExitCode != nil:
		case o.Kind == "step_header" && o.Marker == "" && o.ExitCode == nil && o.StepHeader == nil:
		default:
			add("invalid_observation", i, "unknown kind or marker, or a field the kind does not allow")
			continue
		}
		c := o.Citation
		if job.Status != "present" || c.SourceID != job.ID || c.Start != c.End || c.Start < 1 || c.Start > job.LineCount {
			add("citation_invalid", i, "not one line of the job log")
			continue
		}
		text, ok := f.text[c.Start]
		if !ok {
			add("citation_not_included", i, "line %d is omitted", c.Start)
			continue
		}
		b := vBody(text)
		switch o.Kind {
		case "error_marker":
			if !vMarker(o.Marker, b) {
				add("pattern_mismatch", i, "line %d does not match %s", c.Start, o.Marker)
				continue
			}
		case "nonzero_exit":
			if code, ok := vExit(b); !ok || code != *o.ExitCode {
				add("pattern_mismatch", i, "line %d does not report exit code %d", c.Start, *o.ExitCode)
				continue
			}
		case "step_header":
			if !strings.HasPrefix(b, "##[group]Run ") {
				add("pattern_mismatch", i, "line %d is not a step header", c.Start)
			}
			continue
		}
		h, ok := f.step(c.Start)
		want := (*Citation)(nil)
		if ok {
			want = &Citation{SourceID: job.ID, Start: h, End: h}
		}
		if !reflect.DeepEqual(o.StepHeader, want) {
			add("step_header_mismatch", i, "section 4 gives %s for line %d", describeStep(want), c.Start)
		}
	}

	// Order, and the listed observations against all of them.
	all := f.observations()
	limit := min(len(all), MaxListed)
	expected := map[vObs]bool{}
	for _, k := range all[:limit] {
		expected[k] = true
	}
	listed := map[vObs]bool{}
	var prev vObs
	for i, o := range r.Observations {
		k := obsKey(o)
		if (i > 0 && !prev.less(k)) || !expected[k] || listed[k] {
			add("order_invalid", i, "repeated, out of order, or not among the first %d observations", MaxListed)
		}
		listed[k], prev = true, k
	}
	for _, k := range all[:limit] {
		if !listed[k] {
			add("observation_missing", -1, "no observation for %s", k.describe())
		}
	}

	if !reflect.DeepEqual(r.Counts, f.counts(len(all))) {
		add("counts_mismatch", -1, "counts differ from the included lines")
	}
	if want := f.limitations(d, all[:limit], len(all)); !reflect.DeepEqual(normalLims(r.Limitations), want) {
		add("limitations_mismatch", -1, "limitations differ from what the bundle gives")
	}
	return ps
}

// logFacts is the verifier's own reading of the job log.
type logFacts struct {
	job       *sourceDoc
	text      map[int64]string // included lines
	lineOrder []int64
}

func readLog(job *sourceDoc) *logFacts {
	f := &logFacts{job: job, text: map[int64]string{}}
	for _, l := range job.Lines {
		f.text[l.N] = l.Text
		f.lineOrder = append(f.lineOrder, l.N)
	}
	return f
}

func (f *logFacts) jobLog() JobLog {
	j := f.job
	if j.Status == "missing" {
		return JobLog{SourceID: j.ID, Status: "missing", MissingReason: j.MissingReason}
	}
	lines := map[string]int64{"outside_selected_span": 0, "line_too_long": 0, "line_limit": 0, "redacted": 0}
	for _, o := range j.Omitted {
		lines[o.Reason] += o.End - o.Start + 1
	}
	lc, inc, rng, red := j.LineCount, len(j.Lines), len(j.Omitted), j.Redactions
	return JobLog{SourceID: j.ID, Status: "present", Extent: j.Extent, LineCount: &lc, IncludedLines: &inc,
		OmittedLines: lines, OmittedRanges: &rng, InlineRedactions: &red}
}

// vObs identifies an observation: its line, its kind (0 error_marker, 1
// nonzero_exit, 2 step_header), the marker's rank in section 3 (-1 for an
// unknown marker) and the exit code (-1 when absent).
type vObs struct {
	line int64
	kind int
	rank int
	code int64
}

// less is section 3's order: line, then kind, then marker rank.
func (a vObs) less(b vObs) bool {
	if a.line != b.line {
		return a.line < b.line
	}
	if a.kind != b.kind {
		return a.kind < b.kind
	}
	return a.rank < b.rank
}

func (a vObs) describe() string {
	switch a.kind {
	case 0:
		if a.rank < 0 || a.rank >= len(vMarkerNames) { // only computed keys are described
			return fmt.Sprintf("error_marker at line %d", a.line)
		}
		return fmt.Sprintf("error_marker %s at line %d", vMarkerNames[a.rank], a.line)
	case 1:
		return fmt.Sprintf("nonzero_exit at line %d", a.line)
	}
	return fmt.Sprintf("step_header at line %d", a.line)
}

// observations lists every observation the included lines give, in section
// 3 order.
func (f *logFacts) observations() []vObs {
	var out []vObs
	for _, n := range f.lineOrder {
		b := vBody(f.text[n])
		for _, m := range vMarkerNames {
			if vMarker(m, b) {
				out = append(out, vObs{line: n, kind: 0, rank: vMarkerRank(m), code: -1})
			}
		}
		if code, ok := vExit(b); ok {
			out = append(out, vObs{line: n, kind: 1, code: code})
		}
		if strings.HasPrefix(b, "##[group]Run ") {
			out = append(out, vObs{line: n, kind: 2, code: -1})
		}
	}
	return out
}

func obsKey(o Observation) vObs {
	switch o.Kind {
	case "error_marker":
		return vObs{line: o.Citation.Start, kind: 0, rank: vMarkerRank(o.Marker), code: -1}
	case "nonzero_exit":
		code := int64(-1)
		if o.ExitCode != nil {
			code = *o.ExitCode
		}
		return vObs{line: o.Citation.Start, kind: 1, code: code}
	}
	return vObs{line: o.Citation.Start, kind: 2, code: -1}
}

// step walks back from line n over included lines to the nearest step
// header (section 4).
func (f *logFacts) step(n int64) (int64, bool) {
	h, reason := f.stepReason(n)
	return h, reason == ""
}

func (f *logFacts) stepReason(n int64) (int64, string) {
	for k := n; k > 0; k-- {
		t, ok := f.text[k]
		if !ok {
			return 0, "lines_omitted_before"
		}
		if strings.HasPrefix(vBody(t), "##[group]Run ") {
			return k, ""
		}
	}
	return 0, "no_step_header_before"
}

func (f *logFacts) counts(total int) Counts {
	c := Counts{ErrorMarker: map[string]int{}, Observations: total}
	for _, m := range vMarkerNames {
		c.ErrorMarker[m] = 0
	}
	for _, n := range f.lineOrder {
		b := vBody(f.text[n])
		for _, m := range vMarkerNames {
			if vMarker(m, b) {
				c.ErrorMarker[m]++
			}
		}
		if _, ok := vExit(b); ok {
			c.NonzeroExit++
		}
		if strings.HasPrefix(b, "##[group]Run ") {
			c.StepHeader++
		}
	}
	return c
}

func (f *logFacts) limitations(d *bundleDoc, listed []vObs, total int) []Limitation {
	j := f.job
	var out []Limitation
	i64 := func(v int64) *int64 { return &v }
	in := func(v int) *int { return &v }
	if j.Status == "missing" {
		out = append(out, Limitation{Code: "log_missing", SourceID: j.ID, MissingReason: j.MissingReason})
	} else if j.Extent != "complete" {
		out = append(out, Limitation{Code: "log_incomplete", SourceID: j.ID, Extent: j.Extent})
		for _, k := range listed {
			if k.kind != 2 && k.line == j.LineCount {
				out = append(out, Limitation{Code: "line_may_be_cut", SourceID: j.ID, Line: i64(j.LineCount)})
				break
			}
		}
	}
	var missing []sourceDoc
	for _, s := range d.Sources {
		if s.Kind != "job_log" && s.Status == "missing" {
			missing = append(missing, s)
		}
	}
	sort.Slice(missing, func(a, b int) bool { return missing[a].ID < missing[b].ID })
	for _, s := range missing {
		out = append(out, Limitation{Code: "source_missing", SourceID: s.ID, Kind: s.Kind, MissingReason: s.MissingReason})
	}
	if j.Status == "present" {
		for _, reason := range []string{"outside_selected_span", "line_too_long", "line_limit", "redacted"} {
			var lines int64
			ranges := 0
			for _, o := range j.Omitted {
				if o.Reason == reason {
					lines += o.End - o.Start + 1
					ranges++
				}
			}
			if lines > 0 {
				out = append(out, Limitation{Code: "lines_omitted", SourceID: j.ID, Reason: reason, Count: i64(lines), Ranges: in(ranges)})
			}
		}
		var lines []int64 // lines of listed error_marker and nonzero_exit observations
		for _, k := range listed {
			if k.kind != 2 && (len(lines) == 0 || lines[len(lines)-1] != k.line) {
				lines = append(lines, k.line)
			}
		}
		for _, n := range lines {
			_, before := f.text[n-1]
			_, after := f.text[n+1]
			before = n > 1 && !before
			after = n < j.LineCount && !after
			side := map[[2]bool]string{{true, true}: "both", {true, false}: "before", {false, true}: "after"}[[2]bool{before, after}]
			if side != "" {
				out = append(out, Limitation{Code: "context_omitted", SourceID: j.ID, Line: i64(n), Side: side})
			}
		}
		for _, n := range lines {
			if _, reason := f.stepReason(n); reason != "" {
				out = append(out, Limitation{Code: "step_undetermined", SourceID: j.ID, Line: i64(n), Reason: reason})
			}
		}
	}
	if c := d.Runs[0].Checkout; c.Status == "unresolved" {
		out = append(out, Limitation{Code: "checkout_unresolved", Reason: c.Reason})
	}
	if m := d.Runs[0].Matrix; m.Status == "unresolved" {
		out = append(out, Limitation{Code: "matrix_unresolved", Reason: m.Reason})
	}
	if j.Status == "present" {
		markersSeen := false
		for _, n := range f.lineOrder {
			b := vBody(f.text[n])
			if _, ok := vExit(b); ok {
				markersSeen = true
			}
			for _, m := range vMarkerNames {
				markersSeen = markersSeen || vMarker(m, b)
			}
		}
		if !markersSeen {
			out = append(out, Limitation{Code: "no_markers", SourceID: j.ID})
		}
	}
	if total > MaxListed {
		out = append(out, Limitation{Code: "observations_truncated", Total: in(total), Listed: in(MaxListed)})
	}
	return normalLims(out)
}

func normalLims(l []Limitation) []Limitation {
	if l == nil {
		return []Limitation{}
	}
	return l
}

func describeStep(c *Citation) string {
	if c == nil {
		return "no step header"
	}
	return fmt.Sprintf("step header line %d", c.Start)
}

// The verifier's own pattern code (section 3).

var vMarkerNames = []string{"gha_error", "npm_error", "go_test_fail", "pytest_failed", "python_traceback",
	"go_panic", "error_line", "timeout", "failed_count"}

func vMarkerKnown(m string) bool { return vMarkerRank(m) >= 0 }

func vMarkerRank(m string) int {
	for i, n := range vMarkerNames {
		if n == m {
			return i
		}
	}
	return -1
}

// vBody removes a leading timestamp, checked character by character.
func vBody(t string) string {
	const shape = "dddd-dd-ddTdd:dd:dd"
	if len(t) < len(shape)+2 {
		return t
	}
	for i := 0; i < len(shape); i++ {
		if shape[i] == 'd' {
			if t[i] < '0' || t[i] > '9' {
				return t
			}
		} else if t[i] != shape[i] {
			return t
		}
	}
	i := len(shape)
	if t[i] == '.' {
		k := i + 1
		for k < len(t) && k-i-1 < 9 && t[k] >= '0' && t[k] <= '9' {
			k++
		}
		if k == i+1 {
			return t
		}
		i = k
	}
	if i+1 < len(t) && t[i] == 'Z' && t[i+1] == ' ' {
		return t[i+2:]
	}
	return t
}

func isWord(c byte) bool {
	return c == '_' || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func isLetter(c byte) bool { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') }

func unindent(b string) string {
	i := 0
	for i < len(b) && (b[i] == ' ' || b[i] == '\t') {
		i++
	}
	return b[i:]
}

func vMarker(m, b string) bool {
	u := unindent(b)
	switch m {
	case "gha_error":
		return strings.Index(b, "##[error]") >= 0
	case "npm_error":
		return strings.HasPrefix(b, "npm ERR!") || b == "npm error" || strings.HasPrefix(b, "npm error ")
	case "go_test_fail":
		return strings.HasPrefix(u, "--- FAIL: ") || b == "FAIL" || (len(b) > 4 && b[:4] == "FAIL" && (b[4] == ' ' || b[4] == '\t'))
	case "pytest_failed":
		return strings.HasPrefix(b, "FAILED ")
	case "python_traceback":
		return strings.HasPrefix(u, "Traceback (most recent call last):")
	case "go_panic":
		return strings.HasPrefix(b, "panic: ")
	case "error_line":
		k := 0
		for k < len(u) && isLetter(u[k]) {
			k++
		}
		return k >= 5 && u[k-5:k] == "Error" && strings.HasPrefix(u[k:], ": ")
	case "timeout":
		for _, needle := range []string{"TimeoutError", "Timed out", "timed out"} {
			for from := 0; ; {
				i := strings.Index(b[from:], needle)
				if i < 0 {
					break
				}
				s, e := from+i, from+i+len(needle)
				if (s == 0 || !isWord(b[s-1])) && (e == len(b) || !isWord(b[e])) {
					return true
				}
				from = s + 1
			}
		}
		return false
	case "failed_count":
		for from := 0; ; {
			i := strings.Index(b[from:], " failed")
			if i < 0 {
				return false
			}
			s, e := from+i, from+i+len(" failed")
			p := s
			for p > 0 && b[p-1] >= '0' && b[p-1] <= '9' {
				p--
			}
			if p < s && b[p] != '0' && (p == 0 || !isWord(b[p-1])) && (e == len(b) || !isWord(b[e])) {
				return true
			}
			from = s + 1
		}
	}
	return false
}

// vExit finds the first "Process completed with exit code N" with N of 1-10
// digits, no leading zero, and no digit after it.
func vExit(b string) (int64, bool) {
	const phrase = "Process completed with exit code "
	for from := 0; ; {
		i := strings.Index(b[from:], phrase)
		if i < 0 {
			return 0, false
		}
		s := from + i + len(phrase)
		e := s
		for e < len(b) && b[e] >= '0' && b[e] <= '9' {
			e++
		}
		if n := e - s; n >= 1 && n <= 10 && b[s] != '0' {
			v, _ := strconv.ParseInt(b[s:e], 10, 64)
			return v, true
		}
		from = from + i + 1
	}
}
