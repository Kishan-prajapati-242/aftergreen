package compare

import (
	"path/filepath"
	"testing"
)

// Two-sided evidence for lockfile_root_mismatch and dependency_changed when a
// side lacks the whole dependency section (contracts/comparison-v0.md,
// "Two-sided evidence rule"). The fixtures in testdata/ are dev-07 with a
// devDependencies section on one side only:
//
//   forward: the failed manifest has devDependencies (entry on line 12);
//            the failed lockfile root object (lines 7-13) and the baseline
//            manifest (top-level object, lines 1-11) have none.
//   reverse: the failed lockfile root has devDependencies (entry on line 14)
//            and the baseline manifest has it (entry on line 12); the failed
//            manifest (top-level object, lines 1-11) has none.
//
// These fixtures are structural test inputs, not evaluation cases. Their job
// logs are unchanged copies of dev-07 (a simulated network failure), and their
// manifest and lockfile are deliberately out of sync in a way npm ci would
// reject. They must not be used as evidence that a mismatch caused a failure.

func findObs(r *Result, kind string) []Observation {
	var out []Observation
	for _, o := range r.Observations {
		if o.Kind == kind {
			out = append(out, o)
		}
	}
	return out
}

func TestWholeSectionAbsentCitesBothSides(t *testing.T) {
	cases := []struct {
		fixture string
		want    []Observation
	}{
		{"section-absent-forward.json", []Observation{
			{Kind: "lockfile_root_mismatch", RunRole: "failed",
				Fields: map[string]string{"section": "devDependencies", "name": "@simulated/test-kit", "manifest_spec": "^0.3.0", "lockfile_section": "absent"},
				Citations: []Citation{
					{SourceID: "failed.lockfile", Start: 7, End: 13}, // packages[""] object: no devDependencies section
					{SourceID: "failed.manifest", Start: 12, End: 12},
				}},
			{Kind: "dependency_changed", RunRole: "both",
				Fields: map[string]string{"section": "devDependencies", "name": "@simulated/test-kit", "failed_spec": "^0.3.0", "baseline_section": "absent"},
				Citations: []Citation{
					{SourceID: "baseline.manifest", Start: 1, End: 11}, // top-level object: no devDependencies section
					{SourceID: "failed.manifest", Start: 12, End: 12},
				}},
		}},
		{"section-absent-reverse.json", []Observation{
			{Kind: "lockfile_root_mismatch", RunRole: "failed",
				Fields: map[string]string{"section": "devDependencies", "name": "@simulated/test-kit", "lockfile_spec": "^0.3.0", "manifest_section": "absent"},
				Citations: []Citation{
					{SourceID: "failed.lockfile", Start: 14, End: 14},
					{SourceID: "failed.manifest", Start: 1, End: 11}, // top-level object: no devDependencies section
				}},
			{Kind: "dependency_changed", RunRole: "both",
				Fields: map[string]string{"section": "devDependencies", "name": "@simulated/test-kit", "baseline_spec": "^0.3.0", "failed_section": "absent"},
				Citations: []Citation{
					{SourceID: "baseline.manifest", Start: 12, End: 12},
					{SourceID: "failed.manifest", Start: 1, End: 11}, // top-level object: no devDependencies section
				}},
		}},
	}
	for _, c := range cases {
		t.Run(c.fixture, func(t *testing.T) {
			raw := readFile(t, filepath.Join("testdata", c.fixture))
			res := mustCompare(t, raw)
			if res.Decision != "comparable" {
				t.Errorf("decision %s; want comparable", res.Decision)
			}
			for _, w := range c.want {
				got := findObs(res, w.Kind)
				if len(got) != 1 || jsonText(got[0]) != jsonText(w) {
					t.Errorf("%s:\n got %s\nwant %s", w.Kind, jsonText(got), jsonText(w))
				}
			}
			if problems := Verify(raw, res); len(problems) != 0 {
				t.Errorf("Verify rejected the full result: %s", jsonText(problems))
			}
		})
	}
}

// A result that drops or narrows the containing-object citation is not the
// bundle's comparison.
func TestVerifyRejectsOneSidedSectionEvidence(t *testing.T) {
	raw := readFile(t, filepath.Join("testdata", "section-absent-forward.json"))
	index := func(r *Result, kind string) int {
		for i, o := range r.Observations {
			if o.Kind == kind {
				return i
			}
		}
		t.Fatalf("no %s observation", kind)
		return -1
	}
	cases := []struct {
		name   string
		mutate func(r *Result) int
	}{
		{"lockfile mismatch citing only the manifest", func(r *Result) int {
			i := index(r, "lockfile_root_mismatch")
			r.Observations[i].Citations = []Citation{{SourceID: "failed.manifest", Start: 12, End: 12}}
			return i
		}},
		{"lockfile mismatch citing part of the root object", func(r *Result) int {
			i := index(r, "lockfile_root_mismatch")
			r.Observations[i].Citations[0].End = 12
			return i
		}},
		{"dependency change citing only the failed manifest", func(r *Result) int {
			i := index(r, "dependency_changed")
			r.Observations[i].Citations = []Citation{{SourceID: "failed.manifest", Start: 12, End: 12}}
			return i
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := clone(t, mustCompare(t, raw))
			i := c.mutate(r)
			got := Verify(raw, r)
			if len(got) != 2 || got[0].Code != "unsupported_observation" || got[0].Observation != i ||
				got[1].Code != "observation_missing" || got[1].Observation != -1 {
				t.Fatalf("problems %s; want unsupported_observation at %d, then observation_missing", jsonText(got), i)
			}
		})
	}
}

// Every lockfile_root_mismatch and dependency_changed, in every development
// case and fixture, cites exactly one line range in each of two files.
func TestDependencyObservationsAlwaysCiteBothFiles(t *testing.T) {
	paths, _ := filepath.Glob(filepath.Join(devDir, "bundles", "*.json"))
	more, _ := filepath.Glob(filepath.Join("testdata", "*.json"))
	for _, p := range append(paths, more...) {
		res := mustCompare(t, readFile(t, p))
		for _, o := range res.Observations {
			if o.Kind != "lockfile_root_mismatch" && o.Kind != "dependency_changed" {
				continue
			}
			if len(o.Citations) != 2 || o.Citations[0].SourceID == o.Citations[1].SourceID {
				t.Errorf("%s: %s cites %s; want one range in each of two files", p, o.Kind, jsonText(o.Citations))
			}
		}
	}
}

// setLines replaces a source's text with the given lines, numbered from 1.
func setLines(s *sourceDoc, lines []string) {
	s.Lines = nil
	for i, text := range lines {
		s.Lines = append(s.Lines, lineDoc{N: int64(i + 1), Text: text})
	}
	s.LineCount = int64(len(lines))
}

func texts(s *sourceDoc) []string {
	var out []string
	for _, ln := range s.Lines {
		out = append(out, ln.Text)
	}
	return out
}

func citationFor(t *testing.T, r *Result, kind, source string) Citation {
	t.Helper()
	for _, o := range findObs(r, kind) {
		for _, c := range o.Citations {
			if c.SourceID == source {
				return c
			}
		}
	}
	t.Fatalf("no %s citation of %s in %s", kind, source, kinds(r))
	return Citation{}
}

// The containing object starts at the manifest's opening brace and at the
// lockfile's `""` member name, wherever those lines are.
func TestContainingObjectStartLines(t *testing.T) {
	t.Run("manifest brace after a blank first line", func(t *testing.T) {
		d, err := decodeBundle(readFile(t, filepath.Join("testdata", "section-absent-forward.json")))
		if err != nil {
			t.Fatal(err)
		}
		s := srcOf(d, "baseline.manifest")
		setLines(s, append([]string{""}, texts(s)...)) // "{" now on line 2, "}" on line 12
		got := citationFor(t, compareDoc(d, "test"), "dependency_changed", "baseline.manifest")
		if got.Start != 2 || got.End != 12 {
			t.Fatalf("baseline manifest object cited as %d-%d; want 2-12", got.Start, got.End)
		}
	})
	t.Run(`lockfile "" name and brace on separate lines`, func(t *testing.T) {
		d, err := decodeBundle(readFile(t, filepath.Join("testdata", "section-absent-forward.json")))
		if err != nil {
			t.Fatal(err)
		}
		s := srcOf(d, "failed.lockfile")
		old := texts(s)
		if old[6] != `    "": {` {
			t.Fatalf("unexpected fixture line 7: %q", old[6])
		}
		split := append(append(append([]string{}, old[:6]...), `    "":`, `    {`), old[7:]...) // name on 7, brace on 8, close on 14
		setLines(s, split)
		got := citationFor(t, compareDoc(d, "test"), "lockfile_root_mismatch", "failed.lockfile")
		if got.Start != 7 || got.End != 14 {
			t.Fatalf(`packages[""] cited as %d-%d; want 7-14`, got.Start, got.End)
		}
	})
}

// A dependency moved from devDependencies to dependencies: the cited manifest
// object still contains the name, so the observation must say the section is
// absent rather than imply the name is absent from the object.
func TestMovedDependencyMarksSectionAbsent(t *testing.T) {
	d, err := decodeBundle(readFile(t, filepath.Join("testdata", "section-absent-reverse.json")))
	if err != nil {
		t.Fatal(err)
	}
	m := srcOf(d, "failed.manifest")
	lines := texts(m) // 11-line manifest; dependencies entry on line 9
	lines[8] = `    "@simulated/http-kit": "^1.4.0",`
	lines = append(append(append([]string{}, lines[:9]...), `    "@simulated/test-kit": "^0.3.0"`), lines[9:]...)
	setLines(m, lines)
	r := compareDoc(d, "test")
	var dev *Observation
	for i, o := range r.Observations {
		if o.Kind == "lockfile_root_mismatch" && o.Fields["section"] == "devDependencies" {
			dev = &r.Observations[i]
		}
	}
	if dev == nil || dev.Fields["manifest_section"] != "absent" || dev.Fields["lockfile_spec"] != "^0.3.0" {
		t.Fatalf("devDependencies mismatch: %s", jsonText(dev))
	}
	want := []Citation{{SourceID: "failed.lockfile", Start: 14, End: 14}, {SourceID: "failed.manifest", Start: 1, End: 12}}
	if jsonText(dev.Citations) != jsonText(want) {
		t.Fatalf("devDependencies mismatch cites %s; want %s", jsonText(dev.Citations), jsonText(want))
	}
}

func TestVerifyNilResult(t *testing.T) {
	raw := readFile(t, filepath.Join(devDir, "bundles", "dev-01.json"))
	for _, input := range [][]byte{raw, []byte("{}")} { // result_missing is checked before the bundle
		got := Verify(input, nil)
		if len(got) != 1 || got[0].Code != "result_missing" || got[0].Observation != -1 {
			t.Fatalf("problems %s; want exactly result_missing", jsonText(got))
		}
	}
}
