package compare

import (
	"encoding/json"
	"reflect"

	"aftergreen/contracts/bundle"
)

// Section 6: verification of a comparison result against its bundle.

var kindRoles = map[string][]string{
	"log_error_lines":        {"failed"},
	"exit_code":              {"failed"},
	"error_step":             {"failed"},
	"lockfile_root_mismatch": {"failed"},
	"runner_image":           {"failed", "baseline"},
	"node_version":           {"failed", "baseline"},
	"checkout_sha_shown":     {"failed", "baseline"},
	"source_unchanged":       {"both"},
	"source_changed":         {"both"},
	"dependency_changed":     {"both"},
}

// Verify reports every problem with r as the comparison of raw. It returns
// nil only when every normative value of r equals the bundle's comparison;
// row display strings are not compared.
func Verify(raw []byte, r *Result) []Problem {
	if r == nil {
		return []Problem{{Code: "result_missing", Observation: -1, Detail: "no result to verify"}}
	}
	if f := refuseV1(raw); f != nil {
		return []Problem{{Code: CodeUnsupportedSchema, Observation: -1, Detail: f.Detail}}
	}
	v := bundle.Validate(raw)
	if !v.Accepted() {
		return []Problem{{Code: "bundle_invalid", Observation: -1, Detail: v.Code + " at " + v.Pointer}}
	}
	doc, err := decodeBundle(raw)
	if err != nil {
		return []Problem{{Code: "bundle_invalid", Observation: -1, Detail: err.Error()}}
	}
	want := compareDoc(doc, v.EvidenceSHA256)
	var problems []Problem
	if r.BundleEvidenceSHA256 != v.EvidenceSHA256 {
		problems = append(problems, Problem{Code: "bundle_mismatch", Observation: -1, Detail: "result is for digest " + r.BundleEvidenceSHA256})
	}
	if r.Schema != want.Schema || r.EvidenceClass != want.EvidenceClass || r.Decision != want.Decision ||
		!reflect.DeepEqual(normativeRows(r.Rows), normativeRows(want.Rows)) ||
		!reflect.DeepEqual(nonNilLims(r.Limitations), want.Limitations) {
		problems = append(problems, Problem{Code: "summary_mismatch", Observation: -1,
			Detail: "schema, evidence_class, decision, rows or limitations differ from the bundle's"})
	}

	supported := map[string]bool{}
	var wantKeys []string
	for _, o := range want.Observations {
		k := observationKey(o)
		supported[k] = true
		wantKeys = append(wantKeys, k)
	}
	byID := map[string]*sourceDoc{}
	for i := range doc.Sources {
		byID[doc.Sources[i].ID] = &doc.Sources[i]
	}
	seen := map[string]bool{}
	var gotKeys []string
	observationProblems := false
	for i, o := range r.Observations {
		k := observationKey(o)
		code, detail := checkObservation(o, byID, supported)
		if code == "" && seen[k] {
			code, detail = "duplicate_observation", "repeats an earlier observation"
		}
		if code != "" {
			problems = append(problems, Problem{Code: code, Observation: i, Detail: detail})
			observationProblems = true
			continue
		}
		seen[k] = true
		gotKeys = append(gotKeys, k)
	}
	missing := false
	for i, k := range wantKeys {
		if !seen[k] {
			problems = append(problems, Problem{Code: "observation_missing", Observation: -1,
				Detail: "the bundle produces " + want.Observations[i].Kind + " (" + want.Observations[i].RunRole + ")"})
			missing = true
		}
	}
	if !observationProblems && !missing && !reflect.DeepEqual(gotKeys, wantKeys) {
		problems = append(problems, Problem{Code: "observation_order", Observation: -1, Detail: "observations are not in contract order"})
	}
	return problems
}

func checkObservation(o Observation, byID map[string]*sourceDoc, supported map[string]bool) (string, string) {
	roles, known := kindRoles[o.Kind]
	if !known {
		return "unknown_kind", o.Kind
	}
	if !contains(roles, o.RunRole) {
		return "invalid_run_role", o.RunRole
	}
	for _, c := range o.Citations {
		s := byID[c.SourceID]
		switch {
		case s == nil:
			return "citation_unknown_source", c.SourceID
		case !s.present():
			return "citation_missing_source", c.SourceID
		case o.RunRole != "both" && s.RunRole != o.RunRole:
			return "citation_wrong_run", c.SourceID + " belongs to the " + s.RunRole + " run"
		case c.Start < 1 || c.End < c.Start || c.End > s.LineCount:
			return "citation_out_of_range", c.SourceID
		}
		for _, om := range s.Omitted {
			if om.Start <= c.End && om.End >= c.Start {
				return "citation_includes_omitted", c.SourceID
			}
		}
	}
	if !supported[observationKey(o)] {
		return "unsupported_observation", "the bundle does not produce this observation"
	}
	return "", ""
}

func observationKey(o Observation) string {
	if o.Fields == nil {
		o.Fields = map[string]string{}
	}
	if o.Citations == nil {
		o.Citations = []Citation{}
	}
	data, _ := json.Marshal(o) // map keys are sorted, so the key is canonical
	return string(data)
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// normativeRows keeps field, outcome and effect; display strings are informational.
func normativeRows(rows []Row) []Row {
	out := []Row{}
	for _, r := range rows {
		out = append(out, Row{Field: r.Field, Outcome: r.Outcome, Effect: r.Effect})
	}
	return out
}

func nonNilLims(l []Limitation) []Limitation {
	if l == nil {
		return []Limitation{}
	}
	return l
}
