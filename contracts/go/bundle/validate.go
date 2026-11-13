// Package bundle validates Aftergreen evidence bundles against contract v0 and
// computes their evidence digest. The normative rules are in
// contracts/bundle-v0.md; contracts/cases holds the shared conformance cases.
// Only the standard library is used.
package bundle

import (
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Limits and constants from contracts/bundle-v0.md.
const (
	SchemaVersion       = "aftergreen.bundle.v0"
	MaxInputBytes       = 131072 // 128 KiB of raw input
	MaxDepth            = 16
	MaxSources          = 20
	MaxLinesPerSource   = 500
	MaxOmittedPerSource = 501
	MaxLineBytes        = 2048
	MaxSafeInteger      = 1<<53 - 1
)

// Error codes, in validation-phase order (section 8).
const (
	CodeInputTooLarge      = "input_too_large"
	CodeInvalidUTF8        = "invalid_utf8"
	CodeInvalidJSON        = "invalid_json"
	CodeNestingTooDeep     = "nesting_too_deep"
	CodeDuplicateKey       = "duplicate_key"
	CodeInvalidNumber      = "invalid_number"
	CodeEvaluatorField     = "evaluator_field"
	CodeUnknownField       = "unknown_field"
	CodeSchemaViolation    = "schema_violation"
	CodeTooManySources     = "too_many_sources"
	CodeTooManyLines       = "too_many_lines"
	CodeLineTooLong        = "line_too_long"
	CodeUnknownReference   = "unknown_reference"
	CodeMissingSourceEntry = "missing_source_entry"
	CodeLineMapInvalid     = "line_map_invalid"
	CodeSpanInvalid        = "span_invalid"
	CodeDigestMismatch     = "digest_mismatch"
)

// Codes lists every error code defined by the contract.
var Codes = []string{
	CodeInputTooLarge, CodeInvalidUTF8, CodeInvalidJSON, CodeNestingTooDeep,
	CodeDuplicateKey, CodeInvalidNumber, CodeEvaluatorField, CodeUnknownField,
	CodeSchemaViolation, CodeTooManySources, CodeTooManyLines, CodeLineTooLong,
	CodeUnknownReference, CodeMissingSourceEntry, CodeLineMapInvalid,
	CodeSpanInvalid, CodeDigestMismatch,
}

// Result is the outcome of Validate. Code, Pointer and EvidenceSHA256 are
// normative; Detail is informational only.
type Result struct {
	Code           string // empty when the bundle is accepted
	Pointer        string // RFC 6901 pointer to the failing value
	Detail         string
	EvidenceSHA256 string // set when the bundle is accepted
}

// Accepted reports whether the bundle passed every check.
func (r Result) Accepted() bool { return r.Code == "" }

// Validate checks raw bundle bytes and reports the first failing check.
func Validate(raw []byte) Result {
	if len(raw) > MaxInputBytes {
		return rejected(failAt(CodeInputTooLarge, "", "input is %d bytes; the limit is %d", len(raw), MaxInputBytes))
	}
	if !utf8.Valid(raw) {
		return rejected(failAt(CodeInvalidUTF8, "", "input is not well-formed UTF-8"))
	}
	root, f := parseStrict(raw)
	if f != nil {
		return rejected(f)
	}
	if f := findEvaluatorField(root, ""); f != nil {
		return rejected(f)
	}
	b, f := checkBundle(root)
	if f != nil {
		return rejected(f)
	}
	if f := crossCheck(b); f != nil {
		return rejected(f)
	}
	digest := evidenceDigest(root)
	if digest != b.digest {
		return rejected(failAt(CodeDigestMismatch, "/evidence_sha256", "recomputed evidence digest is %s", digest))
	}
	return Result{EvidenceSHA256: digest}
}

func rejected(f *failure) Result {
	return Result{Code: f.code, Pointer: f.pointer, Detail: f.detail}
}

func schemaErr(pointer, format string, args ...any) *failure {
	return failAt(CodeSchemaViolation, pointer, format, args...)
}

func escapePointer(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// --- Section 2: evaluator-only member names -------------------------------

var reservedNames = []string{
	"acceptable_hypotheses", "answer", "answers", "baseline_applicability",
	"diagnosis", "expected", "fix", "gold", "ground_truth", "injected_fault",
	"repair", "root_cause", "supporting_spans", "unsupported_claims",
	"verified_outcome", "verified_repair",
}

var reservedPrefixes = []string{"expected_", "gold_", "eval_", "evaluator_"}

func isReserved(name string) bool {
	if contains(reservedNames, name) {
		return true
	}
	for _, p := range reservedPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func findEvaluatorField(v *value, ptr string) *failure {
	switch v.kind {
	case kindObject:
		for _, m := range v.members {
			child := ptr + "/" + escapePointer(m.name)
			if isReserved(m.name) {
				return failAt(CodeEvaluatorField, child, "evaluator-only member %q is not allowed in an input bundle", m.name)
			}
			if f := findEvaluatorField(m.value, child); f != nil {
				return f
			}
		}
	case kindArray:
		for i, item := range v.items {
			if f := findEvaluatorField(item, ptr+"/"+strconv.Itoa(i)); f != nil {
				return f
			}
		}
	}
	return nil
}

// --- Section 3: objects and members ----------------------------------------

var (
	reCaseID       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	reID           = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	reSHA          = regexp.MustCompile(`^[0-9a-f]{40}$`)
	reDigest       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reRepoName     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$`)
	reWorkflowPath = regexp.MustCompile(`^\.github/workflows/[A-Za-z0-9._-]{1,100}\.ya?ml$`)
	reBranch       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$`)
	reLabel        = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	reMatrixKey    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	reSegment      = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

var (
	bundleMembers     = []string{"schema", "case_id", "evidence_class", "created_at", "redaction", "runs", "sources", "evidence_sha256"}
	runMembers        = []string{"role", "repository", "workflow", "run_id", "run_attempt", "attempt_started_at", "event", "branch", "head_sha", "job", "checkout", "matrix", "runner"}
	repositoryMembers = []string{"id", "full_name"}
	workflowMembers   = []string{"id", "path"}
	jobMembers        = []string{"id", "name", "conclusion", "started_at", "completed_at"}
	runnerMembers     = []string{"os", "arch", "labels", "evidence"}
	spanMembers       = []string{"source_id", "start", "end"}
	matrixValueFields = []string{"key", "value"}
	sourceMembers     = []string{"id", "kind", "run_role", "status", "path", "revision", "missing_reason", "extent", "line_count", "lines", "omitted"}
	lineMembers       = []string{"n", "text"}
	omittedMembers    = []string{"start", "end", "reason"}

	checkoutReasons = []string{"dynamic_ref", "multiple_checkouts", "log_missing", "reusable_workflow", "output_unverifiable", "no_checkout_step"}
	matrixReasons   = []string{"custom_job_name", "log_missing", "ambiguous"}
	missingReasons  = []string{"expired", "not_found", "too_large", "limit_reached", "access_denied", "not_collected"}
	omittedReasons  = []string{"outside_selected_span", "line_too_long", "line_limit"} // "redacted" is reserved; v0 has no redaction
	requiredKinds   = []string{"job_log", "workflow_file", "manifest", "lockfile"}
)

type bundleDoc struct {
	runs    []*runDoc
	sources []*sourceDoc
	digest  string
}

type runDoc struct {
	ptr            string
	role           string
	repoID         int64
	repoName       string
	workflowPath   string
	attemptStarted string
	jobCompleted   string
	spanLists      [][]spanDoc // checkout, matrix (absent for "none"), runner
}

type spanDoc struct {
	ptr      string
	sourceID string
	start    int64
	end      int64
}

type sourceDoc struct {
	ptr       string
	id        string
	kind      string
	runRole   string
	present   bool
	path      string
	lineCount int64
	lines     []int64 // original line numbers of included lines
	omitted   []rangeDoc
}

type rangeDoc struct {
	start, end int64
	reason     string
}

// obj is an object whose member names have been checked.
type obj struct {
	ptr     string
	order   []member
	members map[string]*value
}

func object(v *value, ptr string, allowed, required []string) (*obj, *failure) {
	if v.kind != kindObject {
		return nil, schemaErr(ptr, "expected an object, found %s", v.kind)
	}
	o := &obj{ptr: ptr, order: v.members, members: make(map[string]*value, len(v.members))}
	for _, m := range v.members {
		if !contains(allowed, m.name) {
			return nil, failAt(CodeUnknownField, ptr+"/"+escapePointer(m.name), "member %q is not allowed here", m.name)
		}
		o.members[m.name] = m.value
	}
	if f := o.require(required...); f != nil {
		return nil, f
	}
	return o, nil
}

func (o *obj) at(name string) string { return o.ptr + "/" + name }

func (o *obj) has(name string) bool {
	_, ok := o.members[name]
	return ok
}

func (o *obj) require(names ...string) *failure {
	for _, name := range names {
		if !o.has(name) {
			return schemaErr(o.at(name), "required member %q is missing", name)
		}
	}
	return nil
}

// onlyForm reports the first member, in document order, that the selected
// form does not allow.
func (o *obj) onlyForm(allowed ...string) *failure {
	for _, m := range o.order {
		if !contains(allowed, m.name) {
			return schemaErr(o.at(m.name), "member %q is not allowed in this form", m.name)
		}
	}
	return nil
}

func (o *obj) get(name string) (*value, *failure) {
	v, ok := o.members[name]
	if !ok {
		return nil, schemaErr(o.at(name), "required member %q is missing", name)
	}
	return v, nil
}

func (o *obj) str(name string) (string, *failure) {
	v, f := o.get(name)
	if f != nil {
		return "", f
	}
	if v.kind != kindString {
		return "", schemaErr(o.at(name), "expected a string, found %s", v.kind)
	}
	return v.str, nil
}

func (o *obj) integer(name string, min int64) (int64, *failure) {
	v, f := o.get(name)
	if f != nil {
		return 0, f
	}
	if v.kind != kindNumber {
		return 0, schemaErr(o.at(name), "expected an integer, found %s", v.kind)
	}
	n, err := strconv.ParseInt(v.num, 10, 64) // the parser guarantees 0..2^53-1
	if err != nil {
		return 0, schemaErr(o.at(name), "integer %s is out of range", v.num)
	}
	if n < min {
		return 0, schemaErr(o.at(name), "must be at least %d", min)
	}
	return n, nil
}

func (o *obj) enum(name string, allowed ...string) (string, *failure) {
	s, f := o.str(name)
	if f != nil {
		return "", f
	}
	if !contains(allowed, s) {
		return "", schemaErr(o.at(name), "%q is not one of %s", s, strings.Join(allowed, ", "))
	}
	return s, nil
}

func (o *obj) match(name string, re *regexp.Regexp) (string, *failure) {
	s, f := o.str(name)
	if f != nil {
		return "", f
	}
	if !re.MatchString(s) {
		return "", schemaErr(o.at(name), "%q does not match %s", s, re)
	}
	return s, nil
}

func (o *obj) timestamp(name string) (string, *failure) {
	s, f := o.str(name)
	if f != nil {
		return "", f
	}
	if !validTimestamp(s) {
		return "", schemaErr(o.at(name), "%q is not a valid YYYY-MM-DDTHH:MM:SSZ timestamp", s)
	}
	return s, nil
}

func (o *obj) display(name string) (string, *failure) {
	s, f := o.str(name)
	if f != nil {
		return "", f
	}
	if len(s) < 1 || len(s) > 256 || hasControl(s, false) {
		return "", schemaErr(o.at(name), "must be 1-256 UTF-8 bytes without control characters")
	}
	return s, nil
}

func (o *obj) array(name string) ([]*value, *failure) {
	v, f := o.get(name)
	if f != nil {
		return nil, f
	}
	if v.kind != kindArray {
		return nil, schemaErr(o.at(name), "expected an array, found %s", v.kind)
	}
	return v.items, nil
}

func (o *obj) child(name string, allowed, required []string) (*obj, *failure) {
	v, f := o.get(name)
	if f != nil {
		return nil, f
	}
	return object(v, o.at(name), allowed, required)
}

// hasControl reports U+0000-U+001F or U+007F; tab is allowed in line text.
func hasControl(s string, allowTab bool) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == 0x7f || (c < 0x20 && !(allowTab && c == '\t')) {
			return true
		}
	}
	return false
}

func validTimestamp(s string) bool {
	if len(s) != 20 {
		return false
	}
	for i := 0; i < 20; i++ {
		c := s[i]
		switch i {
		case 4, 7:
			if c != '-' {
				return false
			}
		case 10:
			if c != 'T' {
				return false
			}
		case 13, 16:
			if c != ':' {
				return false
			}
		case 19:
			if c != 'Z' {
				return false
			}
		default:
			if !isDigit(c) {
				return false
			}
		}
	}
	num := func(a, b int) int {
		n, _ := strconv.Atoi(s[a:b])
		return n
	}
	year, month, day := num(0, 4), num(5, 7), num(8, 10)
	hour, minute, second := num(11, 13), num(14, 16), num(17, 19)
	if month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month) {
		return false
	}
	return hour <= 23 && minute <= 59 && second <= 59
}

func daysInMonth(year, month int) int {
	switch month {
	case 2:
		if year%4 == 0 && (year%100 != 0 || year%400 == 0) {
			return 29
		}
		return 28
	case 4, 6, 9, 11:
		return 30
	default:
		return 31
	}
}

func validRelativePath(p string) bool {
	if len(p) < 1 || len(p) > 256 {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." || !reSegment.MatchString(seg) {
			return false
		}
	}
	return true
}

func lastSegment(p string) string { return p[strings.LastIndexByte(p, '/')+1:] }

func checkBundle(root *value) (*bundleDoc, *failure) {
	o, f := object(root, "", bundleMembers, bundleMembers)
	if f != nil {
		return nil, f
	}
	if _, f := o.enum("schema", SchemaVersion); f != nil {
		return nil, f
	}
	if _, f := o.match("case_id", reCaseID); f != nil {
		return nil, f
	}
	if _, f := o.enum("evidence_class", "simulated"); f != nil {
		return nil, f
	}
	if _, f := o.timestamp("created_at"); f != nil {
		return nil, f
	}
	if _, f := o.enum("redaction", "none"); f != nil {
		return nil, f
	}

	b := &bundleDoc{}
	runs, f := o.array("runs")
	if f != nil {
		return nil, f
	}
	if len(runs) < 1 || len(runs) > 2 {
		return nil, schemaErr(o.at("runs"), "expected 1 or 2 runs, found %d", len(runs))
	}
	for i, rv := range runs {
		r, f := checkRun(rv, o.at("runs")+"/"+strconv.Itoa(i))
		if f != nil {
			return nil, f
		}
		b.runs = append(b.runs, r)
	}
	for i, r := range b.runs {
		want := "failed"
		if i == 1 {
			want = "baseline"
		}
		if r.role != want {
			return nil, schemaErr(r.ptr+"/role", "runs[%d] must have role %q", i, want)
		}
	}

	sources, f := o.array("sources")
	if f != nil {
		return nil, f
	}
	if len(sources) > MaxSources {
		return nil, failAt(CodeTooManySources, o.at("sources"), "%d sources; the limit is %d", len(sources), MaxSources)
	}
	for i, sv := range sources {
		s, f := checkSource(sv, o.at("sources")+"/"+strconv.Itoa(i))
		if f != nil {
			return nil, f
		}
		b.sources = append(b.sources, s)
	}
	for i := 1; i < len(b.sources); i++ {
		if b.sources[i-1].id >= b.sources[i].id {
			return nil, schemaErr(b.sources[i].ptr+"/id", "source ids must be strictly ascending")
		}
	}

	if b.digest, f = o.match("evidence_sha256", reDigest); f != nil {
		return nil, f
	}
	return b, nil
}

func checkRun(v *value, ptr string) (*runDoc, *failure) {
	o, f := object(v, ptr, runMembers, runMembers)
	if f != nil {
		return nil, f
	}
	r := &runDoc{ptr: ptr}
	if r.role, f = o.enum("role", "failed", "baseline"); f != nil {
		return nil, f
	}
	repo, f := o.child("repository", repositoryMembers, repositoryMembers)
	if f != nil {
		return nil, f
	}
	if r.repoID, f = repo.integer("id", 1); f != nil {
		return nil, f
	}
	if r.repoName, f = repo.match("full_name", reRepoName); f != nil {
		return nil, f
	}
	wf, f := o.child("workflow", workflowMembers, workflowMembers)
	if f != nil {
		return nil, f
	}
	if _, f = wf.integer("id", 1); f != nil {
		return nil, f
	}
	if r.workflowPath, f = wf.match("path", reWorkflowPath); f != nil {
		return nil, f
	}
	if _, f = o.integer("run_id", 1); f != nil {
		return nil, f
	}
	if _, f = o.integer("run_attempt", 1); f != nil {
		return nil, f
	}
	if r.attemptStarted, f = o.timestamp("attempt_started_at"); f != nil {
		return nil, f
	}
	if _, f = o.enum("event", "push"); f != nil {
		return nil, f
	}
	if _, f = o.match("branch", reBranch); f != nil {
		return nil, f
	}
	if _, f = o.match("head_sha", reSHA); f != nil {
		return nil, f
	}
	job, f := o.child("job", jobMembers, jobMembers)
	if f != nil {
		return nil, f
	}
	if _, f = job.integer("id", 1); f != nil {
		return nil, f
	}
	if _, f = job.display("name"); f != nil {
		return nil, f
	}
	conclusion, f := job.enum("conclusion", "failure", "success")
	if f != nil {
		return nil, f
	}
	started, f := job.timestamp("started_at")
	if f != nil {
		return nil, f
	}
	completed, f := job.timestamp("completed_at")
	if f != nil {
		return nil, f
	}

	checkout, f := checkCheckout(o)
	if f != nil {
		return nil, f
	}
	r.spanLists = append(r.spanLists, checkout)
	matrix, hasMatrix, f := checkMatrix(o)
	if f != nil {
		return nil, f
	}
	if hasMatrix {
		r.spanLists = append(r.spanLists, matrix)
	}
	runner, f := checkRunner(o)
	if f != nil {
		return nil, f
	}
	r.spanLists = append(r.spanLists, runner)

	want := "failure"
	if r.role == "baseline" {
		want = "success"
	}
	if conclusion != want {
		return nil, schemaErr(job.at("conclusion"), "a %s run's job must have conclusion %q", r.role, want)
	}
	if completed < started {
		return nil, schemaErr(job.at("completed_at"), "completed_at is earlier than started_at")
	}
	r.jobCompleted = completed
	return r, nil
}

func checkCheckout(run *obj) ([]spanDoc, *failure) { return checkCheckoutWith(run, checkoutReasons) }

func checkCheckoutWith(run *obj, reasons []string) ([]spanDoc, *failure) {
	o, f := run.child("checkout", []string{"status", "sha", "reason", "evidence"}, []string{"status"})
	if f != nil {
		return nil, f
	}
	status, f := o.enum("status", "resolved", "unresolved")
	if f != nil {
		return nil, f
	}
	if status == "resolved" {
		if f := o.onlyForm("status", "sha", "evidence"); f != nil {
			return nil, f
		}
		if f := o.require("sha", "evidence"); f != nil {
			return nil, f
		}
		if _, f := o.match("sha", reSHA); f != nil {
			return nil, f
		}
		return spans(o, "evidence", 1, 4)
	}
	if f := o.onlyForm("status", "reason", "evidence"); f != nil {
		return nil, f
	}
	if f := o.require("reason", "evidence"); f != nil {
		return nil, f
	}
	if _, f := o.enum("reason", reasons...); f != nil {
		return nil, f
	}
	return spans(o, "evidence", 0, 4)
}

func checkMatrix(run *obj) ([]spanDoc, bool, *failure) {
	return checkMatrixWith(run, matrixReasons, (*obj).display)
}

// checkMatrixWith checks a Matrix with the given reasons and display-string
// rule: v1 also forbids C1 controls in a matrix value.
func checkMatrixWith(run *obj, reasons []string, display func(*obj, string) (string, *failure)) ([]spanDoc, bool, *failure) {
	o, f := run.child("matrix", []string{"status", "values", "reason", "evidence"}, []string{"status"})
	if f != nil {
		return nil, false, f
	}
	status, f := o.enum("status", "none", "resolved", "unresolved")
	if f != nil {
		return nil, false, f
	}
	switch status {
	case "none":
		return nil, false, o.onlyForm("status")
	case "resolved":
		if f := o.onlyForm("status", "values", "evidence"); f != nil {
			return nil, false, f
		}
		if f := o.require("values", "evidence"); f != nil {
			return nil, false, f
		}
		items, f := o.array("values")
		if f != nil {
			return nil, false, f
		}
		if len(items) < 1 || len(items) > 8 {
			return nil, false, schemaErr(o.at("values"), "expected 1 to 8 matrix values, found %d", len(items))
		}
		keys := make([]string, 0, len(items))
		for i, item := range items {
			mv, f := object(item, o.at("values")+"/"+strconv.Itoa(i), matrixValueFields, matrixValueFields)
			if f != nil {
				return nil, false, f
			}
			key, f := mv.match("key", reMatrixKey)
			if f != nil {
				return nil, false, f
			}
			if _, f := display(mv, "value"); f != nil {
				return nil, false, f
			}
			keys = append(keys, key)
		}
		for i := 1; i < len(keys); i++ {
			if keys[i-1] >= keys[i] {
				return nil, false, schemaErr(o.at("values")+"/"+strconv.Itoa(i)+"/key", "matrix keys must be strictly ascending")
			}
		}
		list, f := spans(o, "evidence", 0, 4)
		return list, true, f
	default:
		if f := o.onlyForm("status", "reason", "evidence"); f != nil {
			return nil, false, f
		}
		if f := o.require("reason", "evidence"); f != nil {
			return nil, false, f
		}
		if _, f := o.enum("reason", reasons...); f != nil {
			return nil, false, f
		}
		list, f := spans(o, "evidence", 0, 4)
		return list, true, f
	}
}

func checkRunner(run *obj) ([]spanDoc, *failure) {
	o, f := run.child("runner", runnerMembers, runnerMembers)
	if f != nil {
		return nil, f
	}
	if _, f := o.enum("os", "Linux", "Windows", "macOS", "unknown"); f != nil {
		return nil, f
	}
	if _, f := o.enum("arch", "X64", "ARM64", "X86", "ARM", "unknown"); f != nil {
		return nil, f
	}
	labels, f := o.array("labels")
	if f != nil {
		return nil, f
	}
	if len(labels) > 10 {
		return nil, schemaErr(o.at("labels"), "at most 10 labels, found %d", len(labels))
	}
	for i, l := range labels {
		if l.kind != kindString || !reLabel.MatchString(l.str) {
			return nil, schemaErr(o.at("labels")+"/"+strconv.Itoa(i), "labels must be strings matching %s", reLabel)
		}
	}
	return spans(o, "evidence", 0, 4)
}

func spans(o *obj, name string, min, max int) ([]spanDoc, *failure) {
	items, f := o.array(name)
	if f != nil {
		return nil, f
	}
	if len(items) < min || len(items) > max {
		return nil, schemaErr(o.at(name), "expected %d to %d spans, found %d", min, max, len(items))
	}
	out := make([]spanDoc, 0, len(items))
	for i, item := range items {
		sp, f := object(item, o.at(name)+"/"+strconv.Itoa(i), spanMembers, spanMembers)
		if f != nil {
			return nil, f
		}
		id, f := sp.match("source_id", reID)
		if f != nil {
			return nil, f
		}
		start, f := sp.integer("start", 0)
		if f != nil {
			return nil, f
		}
		end, f := sp.integer("end", 0)
		if f != nil {
			return nil, f
		}
		out = append(out, spanDoc{ptr: sp.ptr, sourceID: id, start: start, end: end})
	}
	return out, nil
}

func checkSource(v *value, ptr string) (*sourceDoc, *failure) {
	o, f := object(v, ptr, sourceMembers, []string{"id", "kind", "run_role", "status"})
	if f != nil {
		return nil, f
	}
	s := &sourceDoc{ptr: ptr}
	if s.id, f = o.match("id", reID); f != nil {
		return nil, f
	}
	if s.kind, f = o.enum("kind", requiredKinds...); f != nil {
		return nil, f
	}
	if s.runRole, f = o.enum("run_role", "failed", "baseline"); f != nil {
		return nil, f
	}
	status, f := o.enum("status", "present", "missing")
	if f != nil {
		return nil, f
	}

	if s.kind == "job_log" {
		for _, name := range []string{"path", "revision"} {
			if o.has(name) {
				return nil, schemaErr(o.at(name), "%s is not allowed for a job_log source", name)
			}
		}
	} else {
		if s.path, f = o.str("path"); f != nil {
			return nil, f
		}
		ok := validRelativePath(s.path)
		switch s.kind {
		case "workflow_file":
			ok = ok && reWorkflowPath.MatchString(s.path)
		case "manifest":
			ok = ok && lastSegment(s.path) == "package.json"
		case "lockfile":
			ok = ok && lastSegment(s.path) == "package-lock.json"
		}
		if !ok {
			return nil, schemaErr(o.at("path"), "%q is not a valid %s path", s.path, s.kind)
		}
		if _, f = o.match("revision", reSHA); f != nil {
			return nil, f
		}
	}

	if status == "missing" {
		if _, f := o.enum("missing_reason", missingReasons...); f != nil {
			return nil, f
		}
		for _, name := range []string{"extent", "line_count", "lines", "omitted"} {
			if o.has(name) {
				return nil, schemaErr(o.at(name), "%s is not allowed for a missing source", name)
			}
		}
		return s, nil
	}

	s.present = true
	if o.has("missing_reason") {
		return nil, schemaErr(o.at("missing_reason"), "missing_reason is not allowed for a present source")
	}
	if _, f = o.enum("extent", "complete", "prefix"); f != nil {
		return nil, f
	}
	if s.lineCount, f = o.integer("line_count", 0); f != nil {
		return nil, f
	}
	lines, f := o.array("lines")
	if f != nil {
		return nil, f
	}
	if len(lines) > MaxLinesPerSource {
		return nil, failAt(CodeTooManyLines, o.at("lines"), "%d lines; the limit is %d", len(lines), MaxLinesPerSource)
	}
	for i, lv := range lines {
		ln, f := object(lv, o.at("lines")+"/"+strconv.Itoa(i), lineMembers, lineMembers)
		if f != nil {
			return nil, f
		}
		n, f := ln.integer("n", 0)
		if f != nil {
			return nil, f
		}
		text, f := ln.str("text")
		if f != nil {
			return nil, f
		}
		if len(text) > MaxLineBytes {
			return nil, failAt(CodeLineTooLong, ln.at("text"), "line text is %d UTF-8 bytes; the limit is %d", len(text), MaxLineBytes)
		}
		if hasControl(text, true) {
			return nil, schemaErr(ln.at("text"), "line text contains a control character other than tab")
		}
		s.lines = append(s.lines, n)
	}
	omitted, f := o.array("omitted")
	if f != nil {
		return nil, f
	}
	if len(omitted) > MaxOmittedPerSource {
		return nil, schemaErr(o.at("omitted"), "%d omitted ranges; the limit is %d", len(omitted), MaxOmittedPerSource)
	}
	for i, ov := range omitted {
		om, f := object(ov, o.at("omitted")+"/"+strconv.Itoa(i), omittedMembers, omittedMembers)
		if f != nil {
			return nil, f
		}
		start, f := om.integer("start", 0)
		if f != nil {
			return nil, f
		}
		end, f := om.integer("end", 0)
		if f != nil {
			return nil, f
		}
		reason, f := om.enum("reason", omittedReasons...)
		if f != nil {
			return nil, f
		}
		s.omitted = append(s.omitted, rangeDoc{start: start, end: end, reason: reason})
	}
	return s, nil
}

// --- Section 6: cross-checks -----------------------------------------------

func crossCheck(b *bundleDoc) *failure {
	if len(b.runs) == 2 && (b.runs[0].repoID != b.runs[1].repoID || b.runs[0].repoName != b.runs[1].repoName) {
		return schemaErr(b.runs[1].ptr+"/repository", "both runs must use the same repository")
	}
	if len(b.runs) == 2 && b.runs[1].jobCompleted >= b.runs[0].attemptStarted {
		return schemaErr(b.runs[1].ptr+"/job/completed_at", "the baseline job must complete before the failed attempt started at %s", b.runs[0].attemptStarted)
	}
	roles := map[string]bool{}
	for _, r := range b.runs {
		roles[r.role] = true
	}
	for _, s := range b.sources {
		if !roles[s.runRole] {
			return failAt(CodeUnknownReference, s.ptr+"/run_role", "no run has role %q", s.runRole)
		}
	}
	for _, r := range b.runs {
		for _, kind := range requiredKinds {
			var found []*sourceDoc
			for _, s := range b.sources {
				if s.runRole == r.role && s.kind == kind {
					found = append(found, s)
				}
			}
			if len(found) == 0 {
				return failAt(CodeMissingSourceEntry, r.ptr, "the %s run has no %s source; list it with status missing if it could not be obtained", r.role, kind)
			}
			if len(found) > 1 {
				return schemaErr(found[1].ptr+"/kind", "the %s run has more than one %s source", r.role, kind)
			}
		}
	}
	for _, r := range b.runs {
		for _, s := range b.sources {
			if s.runRole == r.role && s.kind == "workflow_file" && s.path != r.workflowPath {
				return schemaErr(s.ptr+"/path", "workflow file path differs from the run's workflow path %q", r.workflowPath)
			}
		}
	}
	for _, s := range b.sources {
		if s.present {
			if f := checkLineMap(s); f != nil {
				return f
			}
		}
	}
	byID := make(map[string]*sourceDoc, len(b.sources))
	for _, s := range b.sources {
		byID[s.id] = s
	}
	for _, r := range b.runs {
		for _, list := range r.spanLists {
			for _, sp := range list {
				if f := checkSpan(sp, r, byID); f != nil {
					return f
				}
			}
		}
	}
	return nil
}

func checkLineMap(s *sourceDoc) *failure {
	linePtr := func(k int) string { return s.ptr + "/lines/" + strconv.Itoa(k) + "/n" }
	rangePtr := func(k int, field string) string { return s.ptr + "/omitted/" + strconv.Itoa(k) + "/" + field }
	for k := 1; k < len(s.lines); k++ {
		if s.lines[k] <= s.lines[k-1] {
			return failAt(CodeLineMapInvalid, linePtr(k), "line numbers must be strictly ascending")
		}
	}
	for k, r := range s.omitted {
		if r.start > r.end {
			return failAt(CodeLineMapInvalid, rangePtr(k, "end"), "omitted range ends before it starts")
		}
		if k > 0 {
			prev := s.omitted[k-1]
			if r.start <= prev.start {
				return failAt(CodeLineMapInvalid, rangePtr(k, "start"), "omitted ranges must be in ascending order")
			}
			if prev.end+1 == r.start && prev.reason == r.reason {
				return failAt(CodeLineMapInvalid, rangePtr(k, "reason"), "adjacent omitted ranges must have different reasons")
			}
		}
	}
	next := int64(1)
	li, oi := 0, 0
	for li < len(s.lines) || oi < len(s.omitted) {
		var start, end int64
		var ptr string
		if li < len(s.lines) && (oi >= len(s.omitted) || s.lines[li] <= s.omitted[oi].start) {
			start, end, ptr = s.lines[li], s.lines[li], linePtr(li)
			li++
		} else {
			start, end, ptr = s.omitted[oi].start, s.omitted[oi].end, rangePtr(oi, "start")
			oi++
		}
		if start != next {
			return failAt(CodeLineMapInvalid, ptr, "expected line %d next, found %d", next, start)
		}
		next = end + 1
	}
	if next != s.lineCount+1 {
		return failAt(CodeLineMapInvalid, s.ptr+"/line_count", "lines and omitted ranges cover 1..%d, not 1..%d", next-1, s.lineCount)
	}
	return nil
}

func checkSpan(sp spanDoc, r *runDoc, byID map[string]*sourceDoc) *failure {
	src := byID[sp.sourceID]
	switch {
	case src == nil:
		return failAt(CodeUnknownReference, sp.ptr+"/source_id", "no source has id %q", sp.sourceID)
	case !src.present:
		return failAt(CodeSpanInvalid, sp.ptr+"/source_id", "source %q is missing", sp.sourceID)
	case src.runRole != r.role:
		return failAt(CodeSpanInvalid, sp.ptr+"/source_id", "source %q belongs to the %s run", sp.sourceID, src.runRole)
	case sp.start < 1:
		return failAt(CodeSpanInvalid, sp.ptr+"/start", "start must be at least 1")
	case sp.end < sp.start:
		return failAt(CodeSpanInvalid, sp.ptr+"/end", "end is before start")
	case sp.end > src.lineCount:
		return failAt(CodeSpanInvalid, sp.ptr+"/end", "end is beyond line_count %d", src.lineCount)
	}
	var included int64
	for _, n := range src.lines {
		if n >= sp.start && n <= sp.end {
			included++
		}
	}
	if included != sp.end-sp.start+1 {
		return failAt(CodeSpanInvalid, sp.ptr, "lines %d-%d of %q are not all included", sp.start, sp.end, sp.sourceID)
	}
	return nil
}
