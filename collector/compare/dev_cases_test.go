package compare

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"aftergreen/contracts/bundle"
)

// The 12 simulated development cases in eval/dev. Expected results live in
// evaluator-only sidecars derived from contracts/comparison-v0.md (see
// eval/dev/README.md).

const devDir = "../../eval/dev"

var wantLabels = []string{
	"ambiguous-exit", "changed-command", "incompatible-matrix-job", "missing-artifact", "missing-configuration",
	"network-failure", "no-baseline", "partial-log", "path-sensitivity", "questionable-checkout",
	"runtime-change", "stale-lockfile",
}

type expectedRow struct {
	Field   string `json:"field"`
	Outcome string `json:"outcome"`
	Effect  string `json:"effect"`
}

type sidecar struct {
	Schema        string `json:"schema"`
	EvaluatorOnly string `json:"evaluator_only"`
	Bundle        string `json:"bundle"`
	Label         string `json:"label"`
	EvidenceClass string `json:"evidence_class"`
	Scenario      string `json:"scenario"`
	Expected      struct {
		Decision     string        `json:"decision"`
		Rows         []expectedRow `json:"rows"`
		Observations []Observation `json:"observations"`
		Limitations  []Limitation  `json:"limitations"`
	} `json:"expected"`
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func loadSidecar(t *testing.T, path string) (sidecar, []byte) {
	t.Helper()
	data := readFile(t, path)
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var sc sidecar
	if err := dec.Decode(&sc); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	if sc.Schema != "aftergreen.eval-sidecar.v0" || sc.EvidenceClass != "simulated" || !strings.HasPrefix(sc.Scenario, "Simulated") {
		t.Fatalf("%s: unexpected sidecar header", path)
	}
	return sc, data
}

func jsonText(v any) string {
	out, _ := json.MarshalIndent(v, "", "  ")
	return string(out)
}

func TestDevCases(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join(devDir, "sidecars", "*.json"))
	if err != nil || len(paths) != 12 {
		t.Fatalf("want 12 sidecars, found %d (%v)", len(paths), err)
	}
	var labels []string
	for _, p := range paths {
		sc, sidecarBytes := loadSidecar(t, p)
		labels = append(labels, sc.Label)
		t.Run(sc.Label, func(t *testing.T) {
			raw := readFile(t, filepath.Join(devDir, "bundles", sc.Bundle))

			// Guards: the input is a valid simulated bundle that does not name its
			// own diagnosis, and the sidecar is rejected as input.
			if r := bundle.Validate(raw); !r.Accepted() {
				t.Fatalf("bundle rejected: %s at %s", r.Code, r.Pointer)
			}
			if bytes.Contains(bytes.ToLower(raw), []byte(sc.Label)) {
				t.Fatalf("bundle text contains its evaluator label %q", sc.Label)
			}
			if r := bundle.Validate(sidecarBytes); r.Code != bundle.CodeEvaluatorField {
				t.Fatalf("sidecar must be rejected as input with evaluator_field, got %q", r.Code)
			}

			got, err := Compare(raw)
			if err != nil {
				t.Fatal(err)
			}
			if got.Schema != Schema || got.EvidenceClass != "simulated" || got.BundleEvidenceSHA256 != bundle.Validate(raw).EvidenceSHA256 {
				t.Fatalf("bad result header: %s %s %s", got.Schema, got.EvidenceClass, got.BundleEvidenceSHA256)
			}
			if got.Decision != sc.Expected.Decision {
				t.Errorf("decision %s; want %s", got.Decision, sc.Expected.Decision)
			}
			var gotRows []expectedRow
			for _, r := range got.Rows {
				gotRows = append(gotRows, expectedRow{Field: r.Field, Outcome: r.Outcome, Effect: r.Effect})
			}
			if len(gotRows) == 0 && len(sc.Expected.Rows) == 0 {
				gotRows = sc.Expected.Rows
			}
			if !reflect.DeepEqual(gotRows, sc.Expected.Rows) {
				t.Errorf("rows:\n got %s\nwant %s", jsonText(gotRows), jsonText(sc.Expected.Rows))
			}
			if !reflect.DeepEqual(normObs(got.Observations), normObs(sc.Expected.Observations)) {
				t.Errorf("observations:\n got %s\nwant %s", jsonText(got.Observations), jsonText(sc.Expected.Observations))
			}
			if !reflect.DeepEqual(normLim(got.Limitations), normLim(sc.Expected.Limitations)) {
				t.Errorf("limitations:\n got %s\nwant %s", jsonText(got.Limitations), jsonText(sc.Expected.Limitations))
			}
			if problems := Verify(raw, got); len(problems) != 0 {
				t.Errorf("Verify rejected the package's own result: %s", jsonText(problems))
			}
		})
	}
	sort.Strings(labels)
	if !reflect.DeepEqual(labels, wantLabels) {
		t.Fatalf("labels %v; want %v", labels, wantLabels)
	}
}

func normObs(in []Observation) []Observation {
	if len(in) == 0 {
		return nil
	}
	return in
}

func normLim(in []Limitation) []Limitation {
	if len(in) == 0 {
		return nil
	}
	return in
}

// Every citation in every result must resolve to included lines of a present
// source of the cited run, with original line numbers.
func TestCitationsResolveToIncludedLines(t *testing.T) {
	paths, _ := filepath.Glob(filepath.Join(devDir, "bundles", "*.json"))
	paths = append(paths, "../../contracts/cases/valid-simulated-stale-lockfile.json", "../../contracts/cases/valid-missing-baseline-log.json")
	for _, p := range paths {
		raw := readFile(t, p)
		res, err := Compare(raw)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		doc, err := decodeBundle(raw)
		if err != nil {
			t.Fatal(err)
		}
		byID := map[string]*sourceDoc{}
		for i := range doc.Sources {
			byID[doc.Sources[i].ID] = &doc.Sources[i]
		}
		for _, o := range res.Observations {
			if len(o.Citations) == 0 {
				t.Errorf("%s: %s has no citation", p, o.Kind)
			}
			for _, c := range o.Citations {
				s := byID[c.SourceID]
				if s == nil || s.Status != "present" || c.Start < 1 || c.End < c.Start || c.End > s.LineCount {
					t.Fatalf("%s: %s cites %+v outside a present source", p, o.Kind, c)
				}
				if o.RunRole != "both" && s.RunRole != o.RunRole {
					t.Fatalf("%s: %s (%s) cites %s from the %s run", p, o.Kind, o.RunRole, c.SourceID, s.RunRole)
				}
				have := map[int64]bool{}
				for _, ln := range s.Lines {
					have[ln.N] = true
				}
				for n := c.Start; n <= c.End; n++ {
					if !have[n] {
						t.Fatalf("%s: %s cites omitted line %d of %s", p, o.Kind, n, c.SourceID)
					}
				}
			}
		}
	}
}
