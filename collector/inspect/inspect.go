package inspect

import (
	"encoding/json"
	"fmt"
	"sort"

	"aftergreen/collector/markers"
	"aftergreen/contracts/bundle"
)

// Schema is the inspection contract's version string.
const Schema = "aftergreen.inspection.v0"

// MaxListed is the number of observations a result lists at most.
const MaxListed = 200

// Reasons are the omission reasons of bundle v1, in contract order.
var Reasons = []string{"outside_selected_span", "line_too_long", "line_limit", "redacted"}

// Result is an inspection (contracts/inspection-v0.md section 2).
type Result struct {
	Schema               string        `json:"schema"`
	BundleSchema         string        `json:"bundle_schema"`
	BundleEvidenceSHA256 string        `json:"bundle_evidence_sha256"`
	EvidenceClass        string        `json:"evidence_class"`
	JobLog               JobLog        `json:"job_log"`
	Observations         []Observation `json:"observations"`
	Counts               Counts        `json:"counts"`
	Limitations          []Limitation  `json:"limitations"`
}

// JobLog holds the job log's facts. The pointer fields are set when the log
// is present, MissingReason when it is missing.
type JobLog struct {
	SourceID         string           `json:"source_id"`
	Status           string           `json:"status"`
	MissingReason    string           `json:"missing_reason,omitempty"`
	Extent           string           `json:"extent,omitempty"`
	LineCount        *int64           `json:"line_count,omitempty"`
	IncludedLines    *int             `json:"included_lines,omitempty"`
	OmittedLines     map[string]int64 `json:"omitted_lines,omitempty"`
	OmittedRanges    *int             `json:"omitted_ranges,omitempty"`
	InlineRedactions *int             `json:"inline_redactions,omitempty"`
}

// Citation cites lines of a source by original line number.
type Citation struct {
	SourceID string `json:"source_id"`
	Start    int64  `json:"start"`
	End      int64  `json:"end"`
}

// Observation says that a section 3 pattern matched an included line.
type Observation struct {
	Kind       string    `json:"kind"`
	Marker     string    `json:"marker,omitempty"`
	ExitCode   *int64    `json:"exit_code,omitempty"`
	Citation   Citation  `json:"citation"`
	StepHeader *Citation `json:"step_header,omitempty"`
}

// Counts are over all included lines, not only the listed observations.
type Counts struct {
	ErrorMarker  map[string]int `json:"error_marker"`
	NonzeroExit  int            `json:"nonzero_exit"`
	StepHeader   int            `json:"step_header"`
	Observations int            `json:"observations"`
}

// Limitation is one entry of section 5; the fields a code does not use are
// empty.
type Limitation struct {
	Code          string `json:"code"`
	SourceID      string `json:"source_id,omitempty"`
	Kind          string `json:"kind,omitempty"`
	MissingReason string `json:"missing_reason,omitempty"`
	Extent        string `json:"extent,omitempty"`
	Reason        string `json:"reason,omitempty"`
	Count         *int64 `json:"count,omitempty"`
	Ranges        *int   `json:"ranges,omitempty"`
	Line          *int64 `json:"line,omitempty"`
	Side          string `json:"side,omitempty"`
	Total         *int   `json:"total,omitempty"`
	Listed        *int   `json:"listed,omitempty"`
}

// InputError reports bytes that bundle v1 validation rejects.
type InputError struct{ Code, Pointer string }

// Error names the validator's code only: Pointer can hold member names from
// the input.
func (e *InputError) Error() string {
	return "not an accepted bundle v1: " + e.Code
}

// The decoded bundle. encoding/json is used only after bundle.ValidateV1 has
// accepted the bytes, which rules out the inputs it would mishandle.
type bundleDoc struct {
	EvidenceClass string `json:"evidence_class"`
	Runs          []struct {
		Checkout statusDoc `json:"checkout"`
		Matrix   statusDoc `json:"matrix"`
	} `json:"runs"`
	Sources []sourceDoc `json:"sources"`
}

type statusDoc struct {
	Status string `json:"status"`
	Reason string `json:"reason"`
}

type sourceDoc struct {
	ID            string `json:"id"`
	Kind          string `json:"kind"`
	Status        string `json:"status"`
	MissingReason string `json:"missing_reason"`
	Extent        string `json:"extent"`
	LineCount     int64  `json:"line_count"`
	Redactions    int    `json:"redactions"`
	Lines         []struct {
		N    int64  `json:"n"`
		Text string `json:"text"`
	} `json:"lines"`
	Omitted []struct {
		Start  int64  `json:"start"`
		End    int64  `json:"end"`
		Reason string `json:"reason"`
	} `json:"omitted"`
}

// decode validates raw as bundle v1 and decodes it.
func decode(raw []byte) (*bundleDoc, string, error) {
	v := bundle.ValidateV1(raw)
	if !v.Accepted() {
		return nil, "", &InputError{Code: v.Code, Pointer: v.Pointer}
	}
	var d bundleDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, "", fmt.Errorf("decoding an accepted bundle: %w", err)
	}
	return &d, v.EvidenceSHA256, nil
}

func jobLogOf(d *bundleDoc) *sourceDoc {
	for i := range d.Sources {
		if d.Sources[i].Kind == "job_log" {
			return &d.Sources[i]
		}
	}
	return nil // unreachable: v1 requires exactly one
}

func ptr[T any](v T) *T { return &v }

// Inspect returns the inspection of raw, or an *InputError if raw is not an
// accepted bundle v1.
func Inspect(raw []byte) (*Result, error) {
	d, digest, err := decode(raw)
	if err != nil {
		return nil, err
	}
	job := jobLogOf(d)
	sid := job.ID
	r := &Result{Schema: Schema, BundleSchema: bundle.SchemaVersionV1, BundleEvidenceSHA256: digest, EvidenceClass: d.EvidenceClass,
		Observations: []Observation{}, Limitations: []Limitation{},
		Counts: Counts{ErrorMarker: map[string]int{}}}
	for _, m := range markers.Names {
		r.Counts.ErrorMarker[m] = 0
	}

	var context map[int64]string
	var steps map[int64]string
	omittedCount := map[string]int64{}
	rangeCount := map[string]int{}
	if job.Status == "missing" {
		r.JobLog = JobLog{SourceID: sid, Status: "missing", MissingReason: job.MissingReason}
		r.Limitations = append(r.Limitations, Limitation{Code: "log_missing", SourceID: sid, MissingReason: job.MissingReason})
	} else {
		for _, reason := range Reasons {
			omittedCount[reason] = 0
		}
		for _, o := range job.Omitted {
			omittedCount[o.Reason] += o.End - o.Start + 1
			rangeCount[o.Reason]++
		}
		// Every line from 1 to line_count is included or omitted (bundle v1
		// section 4), so the at most 500 included lines say which are omitted.
		included := map[int64]bool{}
		for _, l := range job.Lines {
			included[l.N] = true
		}
		r.JobLog = JobLog{SourceID: sid, Status: "present", Extent: job.Extent, LineCount: ptr(job.LineCount),
			IncludedLines: ptr(len(job.Lines)), OmittedLines: omittedCount, OmittedRanges: ptr(len(job.Omitted)),
			InlineRedactions: ptr(job.Redactions)}

		header := map[int64]bool{}
		bodies := make([]string, len(job.Lines))
		for i, l := range job.Lines {
			bodies[i] = markers.Body(l.Text)
			if markers.StepHeader(bodies[i]) {
				header[l.N] = true
			}
		}
		all := []Observation{} // an array, never null, even with no observation
		for i, l := range job.Lines {
			c := Citation{SourceID: sid, Start: l.N, End: l.N}
			for _, m := range markers.ErrorMarkers(bodies[i]) {
				all = append(all, Observation{Kind: "error_marker", Marker: m, Citation: c})
				r.Counts.ErrorMarker[m]++
			}
			if code, ok := markers.ExitCode(bodies[i]); ok {
				all = append(all, Observation{Kind: "nonzero_exit", ExitCode: ptr(code), Citation: c})
				r.Counts.NonzeroExit++
			}
			if header[l.N] {
				all = append(all, Observation{Kind: "step_header", Citation: c})
				r.Counts.StepHeader++
			}
		}
		r.Counts.Observations = len(all)
		if len(all) > MaxListed {
			all = all[:MaxListed]
		}
		context, steps = map[int64]string{}, map[int64]string{}
		lastCited := false // a listed error_marker or nonzero_exit cites line line_count
		for i := range all {
			o := &all[i]
			if o.Kind == "step_header" {
				continue
			}
			n := o.Citation.Start
			lastCited = lastCited || n == job.LineCount
			if h, reason := stepOf(n, header, included); reason == "" {
				o.StepHeader = &Citation{SourceID: sid, Start: h, End: h}
			} else {
				steps[n] = reason
			}
			before := n > 1 && !included[n-1]
			after := n < job.LineCount && !included[n+1]
			switch {
			case before && after:
				context[n] = "both"
			case before:
				context[n] = "before"
			case after:
				context[n] = "after"
			}
		}
		r.Observations = all
		if job.Extent != "complete" {
			r.Limitations = append(r.Limitations, Limitation{Code: "log_incomplete", SourceID: sid, Extent: job.Extent})
			if lastCited {
				r.Limitations = append(r.Limitations, Limitation{Code: "line_may_be_cut", SourceID: sid, Line: ptr(job.LineCount)})
			}
		}
	}

	others := []sourceDoc{}
	for _, s := range d.Sources {
		if s.Kind != "job_log" && s.Status == "missing" {
			others = append(others, s)
		}
	}
	sort.Slice(others, func(a, b int) bool { return others[a].ID < others[b].ID })
	for _, s := range others {
		r.Limitations = append(r.Limitations, Limitation{Code: "source_missing", SourceID: s.ID, Kind: s.Kind, MissingReason: s.MissingReason})
	}
	if job.Status == "present" {
		for _, reason := range Reasons {
			if n := omittedCount[reason]; n > 0 {
				r.Limitations = append(r.Limitations, Limitation{Code: "lines_omitted", SourceID: sid, Reason: reason, Count: ptr(n), Ranges: ptr(rangeCount[reason])})
			}
		}
		for _, n := range sortedKeys(context) {
			r.Limitations = append(r.Limitations, Limitation{Code: "context_omitted", SourceID: sid, Line: ptr(n), Side: context[n]})
		}
		for _, n := range sortedKeys(steps) {
			r.Limitations = append(r.Limitations, Limitation{Code: "step_undetermined", SourceID: sid, Line: ptr(n), Reason: steps[n]})
		}
	}
	run := d.Runs[0]
	if run.Checkout.Status == "unresolved" {
		r.Limitations = append(r.Limitations, Limitation{Code: "checkout_unresolved", Reason: run.Checkout.Reason})
	}
	if run.Matrix.Status == "unresolved" {
		r.Limitations = append(r.Limitations, Limitation{Code: "matrix_unresolved", Reason: run.Matrix.Reason})
	}
	if job.Status == "present" && r.Counts.NonzeroExit == 0 && sumValues(r.Counts.ErrorMarker) == 0 {
		r.Limitations = append(r.Limitations, Limitation{Code: "no_markers", SourceID: sid})
	}
	if r.Counts.Observations > MaxListed {
		r.Limitations = append(r.Limitations, Limitation{Code: "observations_truncated", Total: ptr(r.Counts.Observations), Listed: ptr(MaxListed)})
	}
	return r, nil
}

// stepOf walks back from line n (section 4): it returns the step header line,
// or the reason none is established. It passes at most 500 included lines.
func stepOf(n int64, header, included map[int64]bool) (int64, string) {
	for k := n; k >= 1; k-- {
		if !included[k] {
			return 0, "lines_omitted_before"
		}
		if header[k] {
			return k, ""
		}
	}
	return 0, "no_step_header_before"
}

func sortedKeys(m map[int64]string) []int64 {
	out := make([]int64, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(a, b int) bool { return out[a] < out[b] })
	return out
}

func sumValues(m map[string]int) int {
	t := 0
	for _, v := range m {
		t += v
	}
	return t
}
