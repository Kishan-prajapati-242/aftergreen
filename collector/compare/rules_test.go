package compare

import (
	"path/filepath"
	"strings"
	"testing"
)

// Focused decision-rule tests. Each mutates a decoded development bundle and
// states the outcome the contract requires. They call compareDoc directly
// because a mutated bundle no longer matches its stored digest.

func loadDoc(t *testing.T, name string) *bundleDoc {
	t.Helper()
	doc, err := decodeBundle(readFile(t, filepath.Join(devDir, "bundles", name)))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func runOf(d *bundleDoc, role string) *runDoc {
	for i := range d.Runs {
		if d.Runs[i].Role == role {
			return &d.Runs[i]
		}
	}
	panic("no run " + role)
}

func srcOf(d *bundleDoc, id string) *sourceDoc {
	for i := range d.Sources {
		if d.Sources[i].ID == id {
			return &d.Sources[i]
		}
	}
	panic("no source " + id)
}

// setContent replaces the content of line n, keeping its timestamp.
func setContent(s *sourceDoc, n int64, text string) {
	for i := range s.Lines {
		if s.Lines[i].N == n {
			s.Lines[i].Text = reTimestamp.FindString(s.Lines[i].Text) + text
			return
		}
	}
	panic("no included line")
}

func rowOf(t *testing.T, r *Result, field string) Row {
	t.Helper()
	for _, row := range r.Rows {
		if row.Field == field {
			return row
		}
	}
	t.Fatalf("no row %s", field)
	return Row{}
}

func hasLimitation(r *Result, want Limitation) bool {
	for _, l := range r.Limitations {
		if l == want {
			return true
		}
	}
	return false
}

func kinds(r *Result) string {
	var ks []string
	for _, o := range r.Observations {
		ks = append(ks, o.RunRole+":"+o.Kind)
	}
	return strings.Join(ks, " ")
}

type ruleCase struct {
	name     string
	base     string
	mutate   func(d *bundleDoc)
	decision string
	row      string // field whose outcome/effect is checked
	outcome  string
	effect   string
	limits   []Limitation // limitations that must be present
	absent   []string     // observation kinds (role:kind) that must be absent
	present  []string     // observation kinds (role:kind) that must be present
}

const (
	otherSHA  = "abcdef0000000000000000000000000000000000"
	coffeeSHA = "c0ffee1100000000000000000000000000000000"
)

func TestDecisionRules(t *testing.T) {
	cases := []ruleCase{
		{name: "duplicate attempt", base: "dev-01.json",
			mutate:   func(d *bundleDoc) { runOf(d, "baseline").RunID = runOf(d, "failed").RunID },
			decision: "incompatible", row: "run_identity", outcome: "duplicate_attempt", effect: "incompatible",
			limits: []Limitation{{Code: "comparison_suppressed", Reason: "incompatible"}}, absent: []string{"both:source_changed", "baseline:checkout_sha_shown"}},
		{name: "duplicate job id", base: "dev-01.json",
			mutate:   func(d *bundleDoc) { runOf(d, "baseline").Job.ID = runOf(d, "failed").Job.ID },
			decision: "incompatible", row: "run_identity", outcome: "duplicate_job_id", effect: "incompatible"},
		{name: "earlier attempt of the same run and commit", base: "dev-01.json",
			mutate: func(d *bundleDoc) {
				b, f := runOf(d, "baseline"), runOf(d, "failed")
				b.RunID, b.HeadSHA, f.RunAttempt = f.RunID, f.HeadSHA, 2
			},
			// The baseline's own checkout evidence still shows its old SHA, so it is partial.
			decision: "partial", row: "run_identity", outcome: "earlier_attempt_same_run", effect: "none"},
		{name: "same run on a different commit", base: "dev-01.json",
			mutate: func(d *bundleDoc) {
				runOf(d, "baseline").RunID = runOf(d, "failed").RunID
				runOf(d, "failed").RunAttempt = 2
			},
			decision: "incompatible", row: "run_identity", outcome: "same_run_inconsistent", effect: "incompatible"},
		{name: "same run with a higher baseline attempt", base: "dev-01.json",
			mutate: func(d *bundleDoc) {
				runOf(d, "baseline").RunID = runOf(d, "failed").RunID
				runOf(d, "baseline").RunAttempt = 2
			},
			decision: "incompatible", row: "run_identity", outcome: "same_run_inconsistent", effect: "incompatible"},
		{name: "different workflow", base: "dev-01.json",
			mutate:   func(d *bundleDoc) { runOf(d, "baseline").Workflow.ID = 2002 },
			decision: "incompatible", row: "workflow", outcome: "different_workflow", effect: "incompatible"},
		{name: "different branch", base: "dev-01.json",
			mutate:   func(d *bundleDoc) { runOf(d, "baseline").Branch = "release" },
			decision: "partial", row: "branch", outcome: "different_branch", effect: "partial", present: []string{"both:source_changed"}},
		{name: "renamed job without a matrix is not a known mismatch", base: "dev-01.json",
			mutate: func(d *bundleDoc) {
				b, f := runOf(d, "baseline"), runOf(d, "failed")
				b.Matrix, f.Matrix = matrixDoc{Status: "none"}, matrixDoc{Status: "none"}
				b.Job.Name, f.Job.Name = "test", "unit tests"
			},
			decision: "unknown", row: "job", outcome: "job_identity_unknown", effect: "unknown"},
		{name: "matrix values compared structurally", base: "dev-01.json",
			mutate: func(d *bundleDoc) {
				runOf(d, "failed").Matrix.Values = []matrixValue{{Key: "a", Value: "1,b=2"}, {Key: "b", Value: "3"}}
				runOf(d, "baseline").Matrix.Values = []matrixValue{{Key: "a", Value: "1"}, {Key: "b", Value: "2,b=3"}}
			},
			decision: "comparable", row: "matrix_values", outcome: "values_changed", effect: "none"},
		{name: "different architecture", base: "dev-01.json",
			mutate:   func(d *bundleDoc) { runOf(d, "baseline").Runner.Arch = "ARM64" },
			decision: "partial", row: "runner_arch", outcome: "arch_conflicts_with_log", effect: "partial",
			limits: []Limitation{{Code: "runner_arch_conflict", RunRole: "baseline"}}},
		{name: "different architecture consistent with the logs", base: "dev-01.json",
			mutate: func(d *bundleDoc) {
				runOf(d, "baseline").Runner.Arch = "ARM64"
				setContent(srcOf(d, "baseline.job-log"), 38, "Found in cache @ /opt/hostedtoolcache/node/20.19.5/arm64")
			},
			decision: "incompatible", row: "runner_arch", outcome: "different_arch", effect: "incompatible"},
		{name: "node arch in the log contradicts the declared arch", base: "dev-01.json",
			mutate: func(d *bundleDoc) {
				setContent(srcOf(d, "failed.job-log"), 38, "Found in cache @ /opt/hostedtoolcache/node/20.19.5/arm64")
			},
			decision: "partial", row: "runner_arch", outcome: "arch_conflicts_with_log", effect: "partial",
			limits: []Limitation{{Code: "runner_arch_conflict", RunRole: "failed"}}},
		{name: "different os", base: "dev-01.json",
			mutate:   func(d *bundleDoc) { runOf(d, "baseline").Runner.OS = "Windows" },
			decision: "incompatible", row: "runner_os", outcome: "different_os", effect: "incompatible"},
		{name: "os unknown", base: "dev-01.json",
			mutate:   func(d *bundleDoc) { runOf(d, "failed").Runner.OS = "unknown" },
			decision: "partial", row: "runner_os", outcome: "os_unknown", effect: "partial",
			limits: []Limitation{{Code: "runner_unknown", RunRole: "failed", Reason: "os"}}},
		{name: "runner labels changed", base: "dev-01.json",
			mutate:   func(d *bundleDoc) { runOf(d, "baseline").Runner.Labels = []string{"ubuntu-22.04"} },
			decision: "comparable", row: "runner_labels", outcome: "labels_changed", effect: "none"},
		{name: "baseline matrix unresolved", base: "dev-01.json",
			mutate: func(d *bundleDoc) {
				runOf(d, "baseline").Matrix = matrixDoc{Status: "unresolved", Reason: "custom_job_name", Evidence: []spanDoc{}}
			},
			decision: "partial", row: "matrix_dimensions", outcome: "matrix_unresolved", effect: "partial",
			limits: []Limitation{{Code: "matrix_unresolved", RunRole: "baseline", Reason: "custom_job_name"}}},
		{name: "matrix unresolved keeps identical job names comparable", base: "dev-01.json",
			mutate: func(d *bundleDoc) {
				runOf(d, "baseline").Matrix = matrixDoc{Status: "unresolved", Reason: "custom_job_name", Evidence: []spanDoc{}}
			},
			decision: "partial", row: "job", outcome: "same_logical_job", effect: "none"},
		{name: "baseline checkout unresolved", base: "dev-01.json",
			mutate: func(d *bundleDoc) {
				runOf(d, "baseline").Checkout = checkoutDoc{Status: "unresolved", Reason: "dynamic_ref", Evidence: []spanDoc{}}
			},
			decision: "partial", row: "baseline_checkout", outcome: "checkout_unresolved", effect: "partial",
			limits: []Limitation{{Code: "checkout_unresolved", RunRole: "baseline", Reason: "dynamic_ref"},
				{Code: "revision_unverified", RunRole: "baseline", SourceID: "baseline.lockfile"},
				{Code: "revision_unverified", RunRole: "baseline", SourceID: "baseline.manifest"}},
			absent: []string{"baseline:checkout_sha_shown", "both:dependency_changed"}},
		{name: "unresolved checkout leaves files unverified", base: "dev-01.json",
			mutate: func(d *bundleDoc) {
				runOf(d, "baseline").Checkout = checkoutDoc{Status: "unresolved", Reason: "dynamic_ref", Evidence: []spanDoc{}}
			},
			decision: "partial", row: "file_revisions", outcome: "revisions_unverified", effect: "partial"},
		{name: "checkout sha not in evidence", base: "dev-01.json",
			mutate:   func(d *bundleDoc) { runOf(d, "failed").Checkout.SHA = otherSHA },
			decision: "partial", row: "failed_checkout", outcome: "checkout_sha_not_in_evidence", effect: "partial",
			limits: []Limitation{{Code: "checkout_sha_not_in_evidence", RunRole: "failed"},
				{Code: "revision_unverified", RunRole: "failed", SourceID: "failed.manifest"}},
			absent: []string{"failed:checkout_sha_shown", "failed:lockfile_root_mismatch"}},
		{name: "sha quoted inside an error line is not shown", base: "dev-01.json",
			mutate: func(d *bundleDoc) {
				setContent(srcOf(d, "failed.job-log"), 33, "##[error]fatal: reference is not a tree: "+runOf(d, "failed").HeadSHA)
			},
			decision: "partial", row: "failed_checkout", outcome: "checkout_sha_not_in_evidence", effect: "partial",
			absent: []string{"failed:checkout_sha_shown"}},
		{name: "requested ref is not a checked-out sha", base: "dev-01.json",
			mutate: func(d *bundleDoc) {
				setContent(srcOf(d, "failed.job-log"), 22, "  ref: "+runOf(d, "failed").HeadSHA)
				setContent(srcOf(d, "failed.job-log"), 33, coffeeSHA)
			},
			decision: "partial", row: "failed_checkout", outcome: "checkout_sha_not_in_evidence", effect: "partial",
			absent: []string{"failed:checkout_sha_shown", "failed:lockfile_root_mismatch"}},
		{name: "evidence shows two different shas", base: "dev-01.json",
			mutate:   func(d *bundleDoc) { setContent(srcOf(d, "failed.job-log"), 22, coffeeSHA) },
			decision: "partial", row: "failed_checkout", outcome: "checkout_evidence_conflict", effect: "partial",
			limits: []Limitation{{Code: "checkout_evidence_conflict", RunRole: "failed"}},
			absent: []string{"failed:checkout_sha_shown"}},
		{name: "manifest with omitted lines is not diffed or parsed", base: "dev-01.json",
			mutate: func(d *bundleDoc) {
				s := srcOf(d, "failed.manifest")
				var kept []lineDoc
				for _, ln := range s.Lines {
					if ln.N != 10 {
						kept = append(kept, ln)
					}
				}
				s.Lines = kept
				s.Omitted = []omittedDoc{{Start: 10, End: 10, Reason: "outside_selected_span"}}
			},
			decision: "partial", row: "file_coverage", outcome: "files_incomplete", effect: "partial",
			limits: []Limitation{{Code: "source_partial_lines", RunRole: "failed", SourceID: "failed.manifest"}},
			absent: []string{"failed:lockfile_root_mismatch", "both:dependency_changed"}},
		{name: "workflow revision mismatch", base: "dev-01.json",
			mutate:   func(d *bundleDoc) { srcOf(d, "failed.workflow").Revision = otherSHA },
			decision: "partial", row: "file_revisions", outcome: "revision_mismatch", effect: "partial",
			limits: []Limitation{{Code: "revision_mismatch", RunRole: "failed", SourceID: "failed.workflow", Reason: "head_sha"}}},
		{name: "manifest that is not JSON is not parsed", base: "dev-01.json",
			mutate:   func(d *bundleDoc) { srcOf(d, "failed.manifest").Lines[0].Text = "{{" },
			decision: "comparable", row: "file_coverage", outcome: "files_complete", effect: "none",
			limits: []Limitation{{Code: "not_parsed", RunRole: "failed", SourceID: "failed.manifest", Reason: "invalid_json"}},
			absent: []string{"failed:lockfile_root_mismatch", "both:dependency_changed"}, present: []string{"both:source_changed"}},
		{name: "control character in a dependency name is not parsed", base: "dev-01.json",
			mutate: func(d *bundleDoc) {
				srcOf(d, "failed.manifest").Lines[9].Text = `    "\u001b@simulated/json-tools": "^2.0.0"`
			},
			decision: "comparable", row: "file_coverage", outcome: "files_complete", effect: "none",
			limits: []Limitation{{Code: "not_parsed", RunRole: "failed", SourceID: "failed.manifest", Reason: "control_character"}},
			absent: []string{"failed:lockfile_root_mismatch", "both:dependency_changed"}},
		{name: "lockfile version 1 is not parsed", base: "dev-01.json",
			mutate:   func(d *bundleDoc) { srcOf(d, "failed.lockfile").Lines[3].Text = `  "lockfileVersion": 1,` },
			decision: "comparable", row: "file_coverage", outcome: "files_complete", effect: "none",
			limits: []Limitation{{Code: "not_parsed", RunRole: "failed", SourceID: "failed.lockfile", Reason: "unsupported_lockfile"}},
			absent: []string{"failed:lockfile_root_mismatch"}},
		{name: "no step header before the first error", base: "dev-07.json",
			mutate: func(d *bundleDoc) {
				s := srcOf(d, "failed.job-log")
				for i := range s.Lines {
					s.Lines[i].Text = strings.Replace(s.Lines[i].Text, "##[group]Run ", "##[group]Step ", 1)
				}
			},
			decision: "comparable", row: "log_coverage", outcome: "logs_fully_read", effect: "none",
			limits: []Limitation{{Code: "error_step_undetermined", RunRole: "failed", SourceID: "failed.job-log", Reason: "no_step_header"}},
			absent: []string{"failed:error_step"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := loadDoc(t, c.base)
			c.mutate(d)
			r := compareDoc(d, "test-digest")
			if r == nil {
				t.Fatal("no result")
			}
			if r.Decision != c.decision {
				t.Errorf("decision %s; want %s", r.Decision, c.decision)
			}
			if row := rowOf(t, r, c.row); row.Outcome != c.outcome || row.Effect != c.effect {
				t.Errorf("row %s: %s/%s; want %s/%s", c.row, row.Outcome, row.Effect, c.outcome, c.effect)
			}
			for _, l := range c.limits {
				if !hasLimitation(r, l) {
					t.Errorf("missing limitation %+v in %s", l, jsonText(r.Limitations))
				}
			}
			got := " " + kinds(r) + " "
			for _, k := range c.absent {
				if strings.Contains(got, " "+k+" ") {
					t.Errorf("observation %s must be absent: %s", k, got)
				}
			}
			for _, k := range c.present {
				if !strings.Contains(got, " "+k+" ") {
					t.Errorf("observation %s must be present: %s", k, got)
				}
			}
		})
	}
}

// The contract fixtures (contracts/cases) through the full Compare path.
func TestContractFixtures(t *testing.T) {
	stale, err := Compare(readFile(t, "../../contracts/cases/valid-simulated-stale-lockfile.json"))
	if err != nil {
		t.Fatal(err)
	}
	if stale.Decision != "partial" || rowOf(t, stale, "runner_arch").Outcome != "arch_unknown" {
		t.Errorf("stale-lockfile fixture: %s / %s", stale.Decision, rowOf(t, stale, "runner_arch").Outcome)
	}
	for _, want := range []Limitation{
		{Code: "runner_unknown", RunRole: "failed", Reason: "arch"},
		{Code: "runner_unknown", RunRole: "baseline", Reason: "arch"},
		{Code: "source_partial_lines", RunRole: "failed", SourceID: "failed.job-log"},
		{Code: "error_step_undetermined", RunRole: "failed", SourceID: "failed.job-log", Reason: "omitted_lines_between", Start: 42, End: 60},
	} {
		if !hasLimitation(stale, want) {
			t.Errorf("stale-lockfile fixture lacks %+v: %s", want, jsonText(stale.Limitations))
		}
	}
	if !strings.Contains(" "+kinds(stale)+" ", " failed:lockfile_root_mismatch ") {
		t.Errorf("stale-lockfile fixture: lockfile_root_mismatch missing: %s", kinds(stale))
	}
	// Error lines 46-51 and 59-60 are separated only by omitted lines 52-58,
	// so they are two groups; one group would cite unseen lines.
	var groups []Citation
	for _, o := range stale.Observations {
		if o.Kind == "log_error_lines" {
			groups = append(groups, o.Citations...)
		}
	}
	wantGroups := []Citation{{SourceID: "failed.job-log", Start: 46, End: 51}, {SourceID: "failed.job-log", Start: 59, End: 60}}
	if jsonText(groups) != jsonText(wantGroups) {
		t.Errorf("stale-lockfile fixture error groups %s; want %s", jsonText(groups), jsonText(wantGroups))
	}

	missing, err := Compare(readFile(t, "../../contracts/cases/valid-missing-baseline-log.json"))
	if err != nil {
		t.Fatal(err)
	}
	wantRows := map[string]string{"runner_os": "os_unknown", "runner_arch": "arch_unknown", "baseline_checkout": "checkout_unresolved",
		"file_revisions": "revisions_unverified", "log_coverage": "log_missing"}
	for field, outcome := range wantRows {
		if got := rowOf(t, missing, field).Outcome; got != outcome {
			t.Errorf("missing-log fixture row %s: %s; want %s", field, got, outcome)
		}
	}
	wantLims := []Limitation{
		{Code: "runner_unknown", RunRole: "failed", Reason: "arch"},
		{Code: "checkout_unresolved", RunRole: "baseline", Reason: "log_missing"},
		{Code: "runner_unknown", RunRole: "baseline", Reason: "os_arch"},
		{Code: "source_missing", RunRole: "baseline", SourceID: "baseline.job-log", Reason: "expired"},
		{Code: "revision_unverified", RunRole: "baseline", SourceID: "baseline.lockfile"},
		{Code: "revision_unverified", RunRole: "baseline", SourceID: "baseline.manifest"},
		{Code: "source_partial_lines", RunRole: "failed", SourceID: "failed.job-log"},
		{Code: "error_step_undetermined", RunRole: "failed", SourceID: "failed.job-log", Reason: "omitted_lines_between", Start: 42, End: 60},
	}
	if missing.Decision != "partial" || jsonText(missing.Limitations) != jsonText(wantLims) {
		t.Errorf("missing-log fixture: decision %s, limitations %s", missing.Decision, jsonText(missing.Limitations))
	}
}

func TestInvalidBundleProducesNoResult(t *testing.T) {
	res, err := Compare([]byte(`{"schema":"aftergreen.bundle.v0"}`))
	if res != nil || err == nil {
		t.Fatalf("want an error and no result, got %v, %v", res, err)
	}
	if be, ok := err.(*BundleError); !ok || be.Code != "schema_violation" {
		t.Fatalf("want BundleError schema_violation, got %#v", err)
	}
}
