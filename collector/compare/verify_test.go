package compare

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

// Negative verification cases: citations across omitted lines, citations to
// the wrong place, observations the bundle does not support, and results
// that drop, repeat, reorder or relabel content.

func mustCompare(t *testing.T, raw []byte) *Result {
	t.Helper()
	r, err := Compare(raw)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func clone(t *testing.T, r *Result) *Result {
	t.Helper()
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var out Result
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return &out
}

type want struct {
	code  string
	index int // observation index; -1 for the whole result; last means the appended one
}

const last = -2

func TestVerifyRejects(t *testing.T) {
	dev01 := readFile(t, filepath.Join(devDir, "bundles", "dev-01.json"))
	dev08 := readFile(t, filepath.Join(devDir, "bundles", "dev-08.json"))
	missing := readFile(t, "../../contracts/cases/valid-missing-baseline-log.json")
	c1 := func(sid string, a, b int64) []Citation { return []Citation{{SourceID: sid, Start: a, End: b}} }
	gone := want{"observation_missing", -1} // a corrupted observation also leaves the real one missing

	// dev-01 observation order (sidecar): 0 log_error_lines, 1 exit_code,
	// 2 error_step, 3 runner_image(failed), ... 6 lockfile_root_mismatch,
	// 10 source_unchanged(workflow).
	cases := []struct {
		name   string
		raw    []byte
		mutate func(r *Result)
		want   []want
	}{
		{"error-line citation runs into omitted lines", dev01,
			func(r *Result) { r.Observations[0].Citations[0].End = 57 }, []want{{"citation_includes_omitted", 0}, gone}},
		{"citation to the other run's log", dev01,
			func(r *Result) { r.Observations[3].Citations[0].SourceID = "baseline.job-log" }, []want{{"citation_wrong_run", 3}, gone}},
		{"citation past line_count", dev01,
			func(r *Result) { r.Observations[1].Citations = c1("failed.job-log", 60, 60) }, []want{{"citation_out_of_range", 1}, gone}},
		{"citation to an undeclared source", dev01,
			func(r *Result) { r.Observations[1].Citations = c1("failed.build-log", 55, 55) }, []want{{"citation_unknown_source", 1}, gone}},
		{"citation to a missing source", missing,
			func(r *Result) {
				r.Observations = append(r.Observations, Observation{Kind: "runner_image", RunRole: "baseline",
					Fields: map[string]string{"image": "ubuntu-24.04", "version": "20261026.1"}, Citations: c1("baseline.job-log", 8, 9)})
			}, []want{{"citation_missing_source", last}}},
		{"exit code the cited line does not show", dev01,
			func(r *Result) { r.Observations[1].Fields["exit_code"] = "2" }, []want{{"unsupported_observation", 1}, gone}},
		{"unchanged claim for a manifest that changed", dev01,
			func(r *Result) {
				r.Observations = append(r.Observations, Observation{Kind: "source_unchanged", RunRole: "both",
					Fields:    map[string]string{"kind": "manifest"},
					Citations: []Citation{{SourceID: "baseline.manifest", Start: 1, End: 11}, {SourceID: "failed.manifest", Start: 1, End: 12}}})
			}, []want{{"unsupported_observation", last}}},
		{"causal kind is not a known kind", dev01,
			func(r *Result) {
				r.Observations = append(r.Observations, Observation{Kind: "root_cause", RunRole: "failed",
					Fields: map[string]string{"cause": "stale lockfile"}, Citations: c1("failed.job-log", 47, 47)})
			}, []want{{"unknown_kind", last}}},
		{"cross-run kind given a single run role", dev01,
			func(r *Result) { r.Observations[10].RunRole = "failed" }, []want{{"invalid_run_role", 10}, gone}},
		{"error step claimed across omitted lines", dev08,
			func(r *Result) {
				r.Observations = append(r.Observations, Observation{Kind: "error_step", RunRole: "failed",
					Fields:    map[string]string{"step": "npm test"},
					Citations: []Citation{{SourceID: "failed.job-log", Start: 45, End: 45}, {SourceID: "failed.job-log", Start: 172, End: 172}}})
			}, []want{{"unsupported_observation", last}}},
		{"error-line range spanning an omitted block", dev08,
			func(r *Result) {
				r.Observations = append(r.Observations, Observation{Kind: "log_error_lines", RunRole: "failed",
					Fields: map[string]string{"markers": "actions_error"}, Citations: c1("failed.job-log", 51, 172)})
			}, []want{{"citation_includes_omitted", last}}},
		{"invented dependency change", dev08,
			func(r *Result) {
				r.Observations = append(r.Observations, Observation{Kind: "dependency_changed", RunRole: "both",
					Fields:    map[string]string{"section": "dependencies", "name": "@simulated/left-pad", "failed_spec": "^1.0.0"},
					Citations: c1("failed.manifest", 9, 9)})
			}, []want{{"unsupported_observation", last}}},
		{"repeated observation", dev01,
			func(r *Result) { r.Observations = append(r.Observations, r.Observations[1]) }, []want{{"duplicate_observation", last}}},
		{"dropped lockfile mismatch", dev01,
			func(r *Result) { r.Observations = append(r.Observations[:6:6], r.Observations[7:]...) }, []want{gone}},
		{"reordered observations", dev01,
			func(r *Result) { r.Observations[0], r.Observations[1] = r.Observations[1], r.Observations[0] }, []want{{"observation_order", -1}}},
		{"simulated result relabelled as collected", dev01,
			func(r *Result) { r.EvidenceClass = "collected" }, []want{{"summary_mismatch", -1}}},
		{"display strings are not normative", dev01,
			func(r *Result) {
				for i := range r.Rows {
					r.Rows[i].Failed, r.Rows[i].Baseline = "", ""
				}
			}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := clone(t, mustCompare(t, c.raw))
			c.mutate(r)
			got := Verify(c.raw, r)
			if len(got) != len(c.want) {
				t.Fatalf("problems %s; want %v", jsonText(got), c.want)
			}
			for i, w := range c.want {
				index := w.index
				if index == last {
					index = len(r.Observations) - 1
				}
				if got[i].Code != w.code || got[i].Observation != index {
					t.Fatalf("problem %d: %s at %d; want %s at %d (all: %s)", i, got[i].Code, got[i].Observation, w.code, index, jsonText(got))
				}
			}
		})
	}
}

func TestVerifySummaryAndBundle(t *testing.T) {
	dev01 := readFile(t, filepath.Join(devDir, "bundles", "dev-01.json"))
	r := clone(t, mustCompare(t, dev01))
	r.BundleEvidenceSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
	if got := Verify(dev01, r); len(got) != 1 || got[0].Code != "bundle_mismatch" || got[0].Observation != -1 {
		t.Fatalf("digest change: %s", jsonText(got))
	}
	r = clone(t, mustCompare(t, dev01))
	r.Decision = "partial"
	if got := Verify(dev01, r); len(got) != 1 || got[0].Code != "summary_mismatch" {
		t.Fatalf("decision change: %s", jsonText(got))
	}
	r = clone(t, mustCompare(t, dev01))
	r.Limitations = append(r.Limitations, Limitation{Code: "no_baseline"})
	if got := Verify(dev01, r); len(got) != 1 || got[0].Code != "summary_mismatch" {
		t.Fatalf("limitation change: %s", jsonText(got))
	}
	if got := Verify([]byte("{}"), r); len(got) != 1 || got[0].Code != "bundle_invalid" {
		t.Fatalf("invalid bundle: %s", jsonText(got))
	}
}
