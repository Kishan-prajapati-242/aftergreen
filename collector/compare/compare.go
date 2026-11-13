package compare

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"aftergreen/contracts/bundle"
)

// Compare validates raw bundle bytes and returns their comparison result.
// Bytes the v0 validator rejects produce a *BundleError and no result. A
// bundle v1 is refused by name (unsupported_schema): comparison v0 is
// defined for bundle v0 only, and v1 compatibility has not been designed.
func Compare(raw []byte) (*Result, error) {
	if f := refuseV1(raw); f != nil {
		return nil, f
	}
	v := bundle.Validate(raw)
	if !v.Accepted() {
		return nil, &BundleError{Code: v.Code, Pointer: v.Pointer, Detail: v.Detail}
	}
	doc, err := decodeBundle(raw)
	if err != nil {
		return nil, err
	}
	return compareDoc(doc, v.EvidenceSHA256), nil
}

// CodeUnsupportedSchema is the BundleError code for a bundle v1.
const CodeUnsupportedSchema = "unsupported_schema"

func refuseV1(raw []byte) *BundleError {
	if !bundle.ValidateV1(raw).Accepted() {
		return nil
	}
	return &BundleError{Code: CodeUnsupportedSchema, Pointer: "/schema",
		Detail: "this is a bundle v1; comparison v0 accepts bundle v0 only, and v1 compatibility has not been designed"}
}

// decodeBundle decodes bytes that bundle.Validate has accepted.
func decodeBundle(raw []byte) (*bundleDoc, error) {
	var d bundleDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("compare: decoding a validated bundle: %w", err)
	}
	return &d, nil
}

var (
	reTimestamp = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z `)
	reExitCode  = regexp.MustCompile(`^##\[error\]Process completed with exit code ([0-9]+)\.$`)
	reImage     = regexp.MustCompile(`^Image: (\S+)$`)
	reVersion   = regexp.MustCompile(`^Version: (\S+)$`)
	reNode      = regexp.MustCompile(`^Found in cache @ /opt/hostedtoolcache/node/([0-9]+\.[0-9]+\.[0-9]+)/([A-Za-z0-9_]+)$`)
	reSHALine   = regexp.MustCompile(`^[0-9a-f]{40}$`)
	// Node tool-cache directory names checked against a declared runner arch.
	nodeArch = map[string]string{"x64": "X64", "arm64": "ARM64"}
	// Error markers, in name order (section 4).
	errorMarkers = []struct {
		name string
		re   *regexp.Regexp
	}{
		{"actions_error", regexp.MustCompile(`^##\[error\]`)},
		{"js_error", regexp.MustCompile(`^\s*[A-Za-z]*Error( \[[A-Z0-9_]+\])?: `)},
		{"npm_error", regexp.MustCompile(`^npm (error|ERR!)( |$)`)},
		{"test_failure", regexp.MustCompile(`^\s*✖ `)},
	}
	fileKinds = []string{"workflow_file", "manifest", "lockfile"}
)

// content is a log line's text without its leading timestamp.
func content(text string) string {
	if loc := reTimestamp.FindStringIndex(text); loc != nil {
		return text[loc[1]:]
	}
	return text
}

type runCtx struct {
	doc      *runDoc
	sources  map[string]*sourceDoc // by kind
	checkout string                // checkout outcome
}

type ctx struct {
	doc      *bundleDoc
	byID     map[string]*sourceDoc
	failed   *runCtx
	baseline *runCtx
	parsed   map[string]*parsedJSON // by source ID; nil value = parse failed
	parseErr map[string]string
}

func newCtx(d *bundleDoc) *ctx {
	c := &ctx{doc: d, byID: map[string]*sourceDoc{}, parsed: map[string]*parsedJSON{}, parseErr: map[string]string{}}
	for i := range d.Sources {
		c.byID[d.Sources[i].ID] = &d.Sources[i]
	}
	for i := range d.Runs {
		r := &runCtx{doc: &d.Runs[i], sources: map[string]*sourceDoc{}}
		for j := range d.Sources {
			if d.Sources[j].RunRole == r.doc.Role {
				r.sources[d.Sources[j].Kind] = &d.Sources[j]
			}
		}
		r.checkout = c.checkoutOutcome(r)
		if r.doc.Role == "failed" {
			c.failed = r
		} else {
			c.baseline = r
		}
	}
	return c
}

func (s *sourceDoc) present() bool { return s != nil && s.Status == "present" }

func (s *sourceDoc) line(n int64) (string, bool) {
	i := sort.Search(len(s.Lines), func(i int) bool { return s.Lines[i].N >= n })
	if i < len(s.Lines) && s.Lines[i].N == n {
		return s.Lines[i].Text, true
	}
	return "", false
}

// omittedBetween reports whether any omitted line lies strictly between a and b.
func (s *sourceDoc) omittedBetween(a, b int64) bool {
	for _, o := range s.Omitted {
		if o.Start < b && o.End > a {
			return true
		}
	}
	return false
}

// shaLines returns the SHA lines (included lines inside the run's checkout
// evidence spans whose content is exactly a 40-hex SHA) that show the
// declared SHA, and whether any SHA line shows a different SHA.
func (c *ctx) shaLines(r *runCtx) ([]Citation, bool) {
	var out []Citation
	conflict := false
	seen := map[Citation]bool{}
	for _, sp := range r.doc.Checkout.Evidence {
		s := c.byID[sp.SourceID]
		if !s.present() {
			continue
		}
		for n := sp.Start; n <= sp.End; n++ {
			text, ok := s.line(n)
			if !ok || !reSHALine.MatchString(content(text)) {
				continue
			}
			if content(text) != r.doc.Checkout.SHA {
				conflict = true
				continue
			}
			cit := Citation{SourceID: s.ID, Start: n, End: n}
			if !seen[cit] {
				seen[cit] = true
				out = append(out, cit)
			}
		}
	}
	sortCitations(out)
	return out, conflict
}

func (c *ctx) checkoutOutcome(r *runCtx) string {
	if r.doc.Checkout.Status != "resolved" {
		return "checkout_unresolved"
	}
	shown, conflict := c.shaLines(r)
	switch {
	case len(shown) == 0:
		return "checkout_sha_not_in_evidence"
	case conflict:
		return "checkout_evidence_conflict"
	case r.doc.Checkout.SHA == r.doc.HeadSHA:
		return "checkout_matches_head"
	default:
		return "checkout_differs_from_head"
	}
}

// checkoutShown: a SHA line shows the declared SHA and none contradicts it.
func checkoutShown(r *runCtx) bool {
	return r.checkout == "checkout_matches_head" || r.checkout == "checkout_differs_from_head"
}

// expectedRevision returns the revision a file source must have and which
// SHA it comes from; ok is false when a manifest or lockfile cannot be tied
// to what the job used because the checkout is not shown.
func expectedRevision(r *runCtx, s *sourceDoc) (rev, which string, ok bool) {
	if s.Kind == "workflow_file" {
		return r.doc.HeadSHA, "head_sha", true
	}
	if checkoutShown(r) {
		return r.doc.Checkout.SHA, "checkout_sha", true
	}
	return "", "", false
}

func usable(r *runCtx, s *sourceDoc) bool {
	if !s.present() || s.Extent != "complete" || len(s.Omitted) != 0 {
		return false
	}
	rev, _, ok := expectedRevision(r, s)
	return ok && s.Revision == rev
}

// archConflict: a node_version line in the run's own job log names an arch
// that maps to a different value than the run declares.
func archConflict(r *runCtx) bool {
	log := r.sources["job_log"]
	if r.doc.Runner.Arch == "unknown" || !log.present() {
		return false
	}
	for _, ln := range log.Lines {
		if m := reNode.FindStringSubmatch(content(ln.Text)); m != nil {
			if a, known := nodeArch[m[2]]; known && a != r.doc.Runner.Arch {
				return true
			}
		}
	}
	return false
}

func sortCitations(cs []Citation) {
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].SourceID != cs[j].SourceID {
			return cs[i].SourceID < cs[j].SourceID
		}
		if cs[i].Start != cs[j].Start {
			return cs[i].Start < cs[j].Start
		}
		return cs[i].End < cs[j].End
	})
}

func observation(kind, role string, fields map[string]string, cites ...Citation) Observation {
	cs := append([]Citation{}, cites...)
	sortCitations(cs)
	return Observation{Kind: kind, RunRole: role, Fields: fields, Citations: cs}
}

// compareDoc applies contracts/comparison-v0.md to a decoded bundle.
func compareDoc(d *bundleDoc, digest string) *Result {
	c := newCtx(d)
	res := &Result{Schema: Schema, BundleEvidenceSHA256: digest, EvidenceClass: d.EvidenceClass,
		Rows: []Row{}, Observations: []Observation{}, Limitations: []Limitation{}}
	if c.baseline == nil {
		res.Decision = "not_supplied"
	} else {
		res.Rows = c.rows()
		res.Decision = decide(res.Rows)
	}
	compared := res.Decision == "comparable" || res.Decision == "partial"

	f := c.failed
	log := f.sources["job_log"]
	stepFound := false
	if log.present() {
		res.Observations = append(res.Observations, errorLineObservations(log)...)
		res.Observations = append(res.Observations, exitCodeObservations(log)...)
		if o, ok := errorStep(log); ok {
			res.Observations = append(res.Observations, o)
			stepFound = true
		}
	}
	res.Observations = append(res.Observations, c.runObservations(f)...)
	res.Observations = append(res.Observations, c.lockfileMismatches()...)
	if compared {
		res.Observations = append(res.Observations, c.runObservations(c.baseline)...)
		res.Observations = append(res.Observations, c.sourceComparisons()...)
		res.Observations = append(res.Observations, c.dependencyChanges()...)
	}

	res.Limitations = c.limitations(res.Decision, log, stepFound)
	return res
}

// --- Section 3: rows ---------------------------------------------------------

func row(field, failed, baseline, outcome, effect string) Row {
	return Row{Field: field, Failed: failed, Baseline: baseline, Outcome: outcome, Effect: effect}
}

func (c *ctx) rows() []Row {
	f, b := c.failed.doc, c.baseline.doc
	var rows []Row

	fv := fmt.Sprintf("%d/%d/%d", f.RunID, f.RunAttempt, f.Job.ID)
	bv := fmt.Sprintf("%d/%d/%d", b.RunID, b.RunAttempt, b.Job.ID)
	switch {
	case f.RunID == b.RunID && f.RunAttempt == b.RunAttempt:
		rows = append(rows, row("run_identity", fv, bv, "duplicate_attempt", "incompatible"))
	case f.Job.ID == b.Job.ID:
		rows = append(rows, row("run_identity", fv, bv, "duplicate_job_id", "incompatible"))
	case f.RunID == b.RunID && b.RunAttempt < f.RunAttempt && b.HeadSHA == f.HeadSHA:
		rows = append(rows, row("run_identity", fv, bv, "earlier_attempt_same_run", "none"))
	case f.RunID == b.RunID:
		rows = append(rows, row("run_identity", fv, bv, "same_run_inconsistent", "incompatible"))
	default:
		rows = append(rows, row("run_identity", fv, bv, "distinct_runs", "none"))
	}

	fw := fmt.Sprintf("%d %s", f.Workflow.ID, f.Workflow.Path)
	bw := fmt.Sprintf("%d %s", b.Workflow.ID, b.Workflow.Path)
	if f.Workflow == b.Workflow {
		rows = append(rows, row("workflow", fw, bw, "same_workflow", "none"))
	} else {
		rows = append(rows, row("workflow", fw, bw, "different_workflow", "incompatible"))
	}

	if f.Branch == b.Branch {
		rows = append(rows, row("branch", f.Branch, b.Branch, "same_branch", "none"))
	} else {
		rows = append(rows, row("branch", f.Branch, b.Branch, "different_branch", "partial"))
	}

	fl, fCertain := logicalJob(f)
	bl, bCertain := logicalJob(b)
	switch {
	case f.Job.Name == b.Job.Name || fl == bl:
		rows = append(rows, row("job", f.Job.Name, b.Job.Name, "same_logical_job", "none"))
	case fCertain && bCertain:
		rows = append(rows, row("job", f.Job.Name, b.Job.Name, "different_job", "incompatible"))
	default:
		rows = append(rows, row("job", f.Job.Name, b.Job.Name, "job_identity_unknown", "unknown"))
	}

	fd, bd := matrixDims(f.Matrix), matrixDims(b.Matrix)
	switch {
	case f.Matrix.Status == "unresolved" || b.Matrix.Status == "unresolved":
		rows = append(rows, row("matrix_dimensions", fd, bd, "matrix_unresolved", "partial"))
	case f.Matrix.Status == "none" && b.Matrix.Status == "none":
		rows = append(rows, row("matrix_dimensions", fd, bd, "no_matrix", "none"))
	case f.Matrix.Status == "resolved" && b.Matrix.Status == "resolved" && fd == bd:
		rows = append(rows, row("matrix_dimensions", fd, bd, "same_dimensions", "none"))
	default:
		rows = append(rows, row("matrix_dimensions", fd, bd, "different_dimensions", "incompatible"))
	}

	fmv, bmv := matrixValues(f.Matrix), matrixValues(b.Matrix)
	switch {
	case f.Matrix.Status != "resolved" || b.Matrix.Status != "resolved" || fd != bd:
		rows = append(rows, row("matrix_values", fmv, bmv, "not_compared", "none"))
	case equalValues(f.Matrix.Values, b.Matrix.Values): // structural: values may contain "," or "="
		rows = append(rows, row("matrix_values", fmv, bmv, "same_values", "none"))
	default:
		rows = append(rows, row("matrix_values", fmv, bmv, "values_changed", "none"))
	}

	rows = append(rows, platformRow("runner_os", f.Runner.OS, b.Runner.OS, "os"))
	if f.Runner.Arch != "unknown" && b.Runner.Arch != "unknown" && (archConflict(c.failed) || archConflict(c.baseline)) {
		rows = append(rows, row("runner_arch", f.Runner.Arch, b.Runner.Arch, "arch_conflicts_with_log", "partial"))
	} else {
		rows = append(rows, platformRow("runner_arch", f.Runner.Arch, b.Runner.Arch, "arch"))
	}

	flab, blab := labelSet(f.Runner.Labels), labelSet(b.Runner.Labels)
	if flab == blab {
		rows = append(rows, row("runner_labels", flab, blab, "same_labels", "none"))
	} else {
		rows = append(rows, row("runner_labels", flab, blab, "labels_changed", "none"))
	}

	rows = append(rows, row("failed_checkout", checkoutValue(f), "", c.failed.checkout, checkoutEffect(c.failed.checkout)))
	rows = append(rows, row("baseline_checkout", "", checkoutValue(b), c.baseline.checkout, checkoutEffect(c.baseline.checkout)))

	fm, fu := revisionProblems(c.failed)
	bm, bu := revisionProblems(c.baseline)
	switch {
	case fm != "" || bm != "":
		rows = append(rows, row("file_revisions", orConsistent(fm), orConsistent(bm), "revision_mismatch", "partial"))
	case fu != "" || bu != "":
		rows = append(rows, row("file_revisions", orConsistent(fu), orConsistent(bu), "revisions_unverified", "partial"))
	default:
		rows = append(rows, row("file_revisions", "consistent", "consistent", "revisions_consistent", "none"))
	}

	fi, bi := incompleteFiles(c.failed), incompleteFiles(c.baseline)
	if fi == "" && bi == "" {
		rows = append(rows, row("file_coverage", "complete", "complete", "files_complete", "none"))
	} else {
		rows = append(rows, row("file_coverage", orComplete(fi), orComplete(bi), "files_incomplete", "partial"))
	}

	fls, bls := logState(c.failed), logState(c.baseline)
	switch {
	case fls == "missing" || bls == "missing":
		rows = append(rows, row("log_coverage", fls, bls, "log_missing", "partial"))
	case fls == "prefix" || bls == "prefix":
		rows = append(rows, row("log_coverage", fls, bls, "log_prefix", "partial"))
	default:
		rows = append(rows, row("log_coverage", fls, bls, "logs_fully_read", "none"))
	}
	return rows
}

func equalValues(a, b []matrixValue) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func decide(rows []Row) string {
	rank := map[string]int{"none": 0, "partial": 1, "unknown": 2, "incompatible": 3}
	worst := 0
	for _, r := range rows {
		if rank[r.Effect] > worst {
			worst = rank[r.Effect]
		}
	}
	return []string{"comparable", "partial", "unknown", "incompatible"}[worst]
}

// logicalJob returns the job name without a verified matrix suffix, and
// whether that logical name is certain. Only a verified suffix makes it
// certain: v0 has no job key, so any other name may be a display name.
func logicalJob(r *runDoc) (string, bool) {
	name := r.Job.Name
	if r.Matrix.Status == "resolved" {
		if i := strings.LastIndex(name, " ("); i >= 0 && strings.HasSuffix(name, ")") {
			parts := strings.Split(name[i+2:len(name)-1], ", ")
			var vals []string
			for _, v := range r.Matrix.Values {
				vals = append(vals, v.Value)
			}
			sort.Strings(parts)
			sort.Strings(vals)
			if strings.Join(parts, "\x00") == strings.Join(vals, "\x00") && len(parts) == len(vals) {
				return name[:i], true
			}
		}
	}
	return name, false
}

func matrixDims(m matrixDoc) string {
	if m.Status != "resolved" {
		return m.Status
	}
	var keys []string
	for _, v := range m.Values {
		keys = append(keys, v.Key)
	}
	return strings.Join(keys, ",") // already ascending (bundle v0 rule)
}

func matrixValues(m matrixDoc) string {
	if m.Status != "resolved" {
		return m.Status
	}
	var kv []string
	for _, v := range m.Values {
		kv = append(kv, v.Key+"="+v.Value)
	}
	return strings.Join(kv, ",")
}

func platformRow(field, f, b, what string) Row {
	switch {
	case f == "unknown" || b == "unknown":
		return row(field, f, b, what+"_unknown", "partial")
	case f == b:
		return row(field, f, b, "same_"+what, "none")
	default:
		return row(field, f, b, "different_"+what, "incompatible")
	}
}

func labelSet(labels []string) string {
	seen := map[string]bool{}
	var out []string
	for _, l := range labels {
		if !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func checkoutValue(r *runDoc) string {
	if r.Checkout.Status != "resolved" {
		return "unresolved: " + r.Checkout.Reason
	}
	return r.Checkout.SHA
}

func checkoutEffect(outcome string) string {
	if outcome == "checkout_matches_head" {
		return "none"
	}
	return "partial"
}

// revisionProblems lists present file sources whose revision differs from the
// expected one, and present manifests or lockfiles with no expected revision.
func revisionProblems(r *runCtx) (mismatched, unverified string) {
	var mis, unv []string
	for _, kind := range fileKinds {
		s := r.sources[kind]
		if !s.present() {
			continue
		}
		rev, _, ok := expectedRevision(r, s)
		switch {
		case !ok:
			unv = append(unv, s.ID)
		case s.Revision != rev:
			mis = append(mis, s.ID)
		}
	}
	return strings.Join(mis, ","), strings.Join(unv, ",")
}

func incompleteFiles(r *runCtx) string {
	var ids []string
	for _, kind := range fileKinds {
		s := r.sources[kind]
		if !s.present() || s.Extent != "complete" || len(s.Omitted) != 0 {
			ids = append(ids, s.ID)
		}
	}
	return strings.Join(ids, ",")
}

func logState(r *runCtx) string {
	s := r.sources["job_log"]
	switch {
	case !s.present():
		return "missing"
	case s.Extent == "prefix":
		return "prefix"
	default:
		return "complete"
	}
}

func orConsistent(s string) string {
	if s == "" {
		return "consistent"
	}
	return s
}

func orComplete(s string) string {
	if s == "" {
		return "complete"
	}
	return s
}

// --- Section 4: observations -------------------------------------------------

func markersOf(text string) []string {
	var out []string
	for _, m := range errorMarkers {
		if m.re.MatchString(text) {
			out = append(out, m.name)
		}
	}
	return out
}

func errorLineObservations(log *sourceDoc) []Observation {
	var out []Observation
	var start, end int64
	marks := map[string]bool{}
	flush := func() {
		if len(marks) == 0 {
			return
		}
		var names []string
		for n := range marks {
			names = append(names, n)
		}
		sort.Strings(names)
		out = append(out, observation("log_error_lines", "failed", map[string]string{"markers": strings.Join(names, ",")},
			Citation{SourceID: log.ID, Start: start, End: end}))
		marks = map[string]bool{}
	}
	for _, ln := range log.Lines {
		ms := markersOf(content(ln.Text))
		if len(ms) == 0 {
			flush()
			continue
		}
		if len(marks) > 0 && ln.N != end+1 {
			flush()
		}
		if len(marks) == 0 {
			start = ln.N
		}
		end = ln.N
		for _, m := range ms {
			marks[m] = true
		}
	}
	flush()
	return out
}

func exitCodeObservations(log *sourceDoc) []Observation {
	var out []Observation
	for _, ln := range log.Lines {
		if m := reExitCode.FindStringSubmatch(content(ln.Text)); m != nil {
			out = append(out, observation("exit_code", "failed", map[string]string{"exit_code": m[1]},
				Citation{SourceID: log.ID, Start: ln.N, End: ln.N}))
		}
	}
	return out
}

// errorStepLines finds E (first ##[error] line) and H (last step header
// before E). It reports a reason when no error_step can be emitted.
func errorStepLines(log *sourceDoc) (h, e lineDoc, reason string) {
	ei := -1
	for i, ln := range log.Lines {
		if strings.HasPrefix(content(ln.Text), "##[error]") {
			ei = i
			break
		}
	}
	if ei < 0 {
		return h, e, "no_error_marker"
	}
	e = log.Lines[ei]
	hi := -1
	for i := ei - 1; i >= 0; i-- {
		if name := strings.TrimPrefix(content(log.Lines[i].Text), "##[group]Run "); name != content(log.Lines[i].Text) && name != "" {
			hi = i
			break
		}
	}
	if hi < 0 {
		return h, e, "no_step_header"
	}
	h = log.Lines[hi]
	if log.omittedBetween(h.N, e.N) {
		return h, e, "omitted_lines_between"
	}
	return h, e, ""
}

func errorStep(log *sourceDoc) (Observation, bool) {
	h, e, reason := errorStepLines(log)
	if reason != "" {
		return Observation{}, false
	}
	step := strings.TrimPrefix(content(h.Text), "##[group]Run ")
	return observation("error_step", "failed", map[string]string{"step": step},
		Citation{SourceID: log.ID, Start: h.N, End: h.N}, Citation{SourceID: log.ID, Start: e.N, End: e.N}), true
}

// runObservations: runner_image, node_version, checkout_sha_shown for one run.
func (c *ctx) runObservations(r *runCtx) []Observation {
	var out []Observation
	role := r.doc.Role
	if log := r.sources["job_log"]; log.present() {
		for i, ln := range log.Lines {
			if content(ln.Text) != "##[group]Runner Image" || i+2 >= len(log.Lines) {
				continue
			}
			a, b := log.Lines[i+1], log.Lines[i+2]
			if a.N != ln.N+1 || b.N != ln.N+2 {
				continue
			}
			mi, mv := reImage.FindStringSubmatch(content(a.Text)), reVersion.FindStringSubmatch(content(b.Text))
			if mi != nil && mv != nil {
				out = append(out, observation("runner_image", role, map[string]string{"image": mi[1], "version": mv[1]},
					Citation{SourceID: log.ID, Start: a.N, End: b.N}))
				break
			}
		}
		for _, ln := range log.Lines {
			if m := reNode.FindStringSubmatch(content(ln.Text)); m != nil {
				out = append(out, observation("node_version", role, map[string]string{"version": m[1], "arch": m[2]},
					Citation{SourceID: log.ID, Start: ln.N, End: ln.N}))
			}
		}
	}
	if checkoutShown(r) {
		matches := "no"
		if r.checkout == "checkout_matches_head" {
			matches = "yes"
		}
		shown, _ := c.shaLines(r)
		out = append(out, observation("checkout_sha_shown", role,
			map[string]string{"sha": r.doc.Checkout.SHA, "matches_head": matches}, shown...))
	}
	return out
}

func lineTexts(s *sourceDoc) []string {
	out := make([]string, len(s.Lines))
	for i, ln := range s.Lines {
		out[i] = ln.Text
	}
	return out
}

func (c *ctx) sourceComparisons() []Observation {
	var out []Observation
	for _, kind := range fileKinds {
		fs, bs := c.failed.sources[kind], c.baseline.sources[kind]
		if !usable(c.failed, fs) || !usable(c.baseline, bs) || fs.LineCount == 0 || bs.LineCount == 0 {
			continue
		}
		b, f := lineTexts(bs), lineTexts(fs)
		nb, nf := len(b), len(f)
		p := 0
		for p < nb && p < nf && b[p] == f[p] {
			p++
		}
		if p == nb && p == nf {
			out = append(out, observation("source_unchanged", "both", map[string]string{"kind": kind},
				Citation{SourceID: bs.ID, Start: 1, End: int64(nb)}, Citation{SourceID: fs.ID, Start: 1, End: int64(nf)}))
			continue
		}
		s := 0
		for s < nb-p && s < nf-p && b[nb-1-s] == f[nf-1-s] {
			s++
		}
		var cites []Citation
		if p+1 <= nb-s {
			cites = append(cites, Citation{SourceID: bs.ID, Start: int64(p + 1), End: int64(nb - s)})
		}
		if p+1 <= nf-s {
			cites = append(cites, Citation{SourceID: fs.ID, Start: int64(p + 1), End: int64(nf - s)})
		}
		out = append(out, observation("source_changed", "both", map[string]string{
			"kind": kind, "common_prefix_lines": fmt.Sprint(p), "common_suffix_lines": fmt.Sprint(s)}, cites...))
	}
	return out
}

// --- Section 5: limitations --------------------------------------------------

func (c *ctx) limitations(decision string, log *sourceDoc, stepFound bool) []Limitation {
	out := []Limitation{}
	switch decision {
	case "not_supplied":
		out = append(out, Limitation{Code: "no_baseline"})
	case "incompatible", "unknown":
		out = append(out, Limitation{Code: "comparison_suppressed", Reason: decision})
	}
	for _, r := range []*runCtx{c.failed, c.baseline} {
		if r == nil {
			continue
		}
		role := r.doc.Role
		switch r.checkout {
		case "checkout_unresolved":
			out = append(out, Limitation{Code: "checkout_unresolved", RunRole: role, Reason: r.doc.Checkout.Reason})
		case "checkout_sha_not_in_evidence", "checkout_evidence_conflict":
			out = append(out, Limitation{Code: r.checkout, RunRole: role})
		}
		if r.doc.Matrix.Status == "unresolved" {
			out = append(out, Limitation{Code: "matrix_unresolved", RunRole: role, Reason: r.doc.Matrix.Reason})
		}
		osU, archU := r.doc.Runner.OS == "unknown", r.doc.Runner.Arch == "unknown"
		switch {
		case osU && archU:
			out = append(out, Limitation{Code: "runner_unknown", RunRole: role, Reason: "os_arch"})
		case osU:
			out = append(out, Limitation{Code: "runner_unknown", RunRole: role, Reason: "os"})
		case archU:
			out = append(out, Limitation{Code: "runner_unknown", RunRole: role, Reason: "arch"})
		}
		if archConflict(r) {
			out = append(out, Limitation{Code: "runner_arch_conflict", RunRole: role})
		}
	}
	for i := range c.doc.Sources {
		s := &c.doc.Sources[i]
		r := c.runOf(s.RunRole)
		if !s.present() {
			out = append(out, Limitation{Code: "source_missing", RunRole: s.RunRole, SourceID: s.ID, Reason: s.MissingReason})
			continue
		}
		if s.Extent == "prefix" {
			out = append(out, Limitation{Code: "source_prefix", RunRole: s.RunRole, SourceID: s.ID})
		}
		if len(s.Omitted) != 0 {
			out = append(out, Limitation{Code: "source_partial_lines", RunRole: s.RunRole, SourceID: s.ID})
		}
		if s.Kind == "job_log" {
			continue
		}
		rev, which, ok := expectedRevision(r, s)
		switch {
		case !ok:
			out = append(out, Limitation{Code: "revision_unverified", RunRole: s.RunRole, SourceID: s.ID})
		case s.Revision != rev:
			out = append(out, Limitation{Code: "revision_mismatch", RunRole: s.RunRole, SourceID: s.ID, Reason: which})
		}
	}
	if log.present() && !stepFound {
		h, e, reason := errorStepLines(log)
		l := Limitation{Code: "error_step_undetermined", RunRole: "failed", SourceID: log.ID, Reason: reason}
		if reason == "omitted_lines_between" {
			l.Start, l.End = h.N, e.N
		}
		out = append(out, l)
	}
	for i := range c.doc.Sources {
		if reason, failed := c.parseErr[c.doc.Sources[i].ID]; failed {
			s := &c.doc.Sources[i]
			out = append(out, Limitation{Code: "not_parsed", RunRole: s.RunRole, SourceID: s.ID, Reason: reason})
		}
	}
	return out
}

func (c *ctx) runOf(role string) *runCtx {
	if role == "failed" {
		return c.failed
	}
	return c.baseline
}
