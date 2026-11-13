package bundle

import (
	"strconv"
	"unicode/utf8"
)

// Contract v1 (contracts/bundle-v1.md): collected public evidence for one
// failed job. It shares v0's byte limits, strict JSON profile, evaluator-name
// scan, object procedure, line map, span rules and canonical encoding; this
// file holds what differs.

// SchemaVersionV1 is the v1 version string.
const SchemaVersionV1 = "aftergreen.bundle.v1"

// RedactionRulesV1 is the only redaction rule set v1 names.
const RedactionRulesV1 = "aftergreen.redaction.1"

const digestTagV1 = "aftergreen.bundle.evidence.v1\n"

var (
	evidenceMembersV1   = []string{"schema", "evidence_class", "collection", "redaction", "runs", "sources"}
	bundleMembersV1     = []string{"schema", "case_id", "evidence_class", "created_at", "collection", "redaction", "runs", "sources", "evidence_sha256"}
	collectionMembersV1 = []string{"tool", "api_version", "metadata_authentication"}
	repositoryMembersV1 = []string{"id", "full_name", "visibility"}
	sourceMembersV1     = []string{"id", "kind", "run_role", "status", "path", "revision", "missing_reason", "extent",
		"received_bytes", "received_sha256", "authentication", "line_count", "redactions", "lines", "omitted"}
	presentOnlyV1 = []string{"extent", "received_bytes", "received_sha256", "authentication", "line_count", "redactions", "lines", "omitted"}

	checkoutReasonsV1 = append(append([]string(nil), checkoutReasons...), "workflow_not_collected")
	matrixReasonsV1   = append(append([]string(nil), matrixReasons...), "workflow_not_collected")
	missingReasonsV1  = append(append([]string(nil), missingReasons...), "transfer_failed", "redirect_rejected")
	omittedReasonsV1  = []string{"outside_selected_span", "line_too_long", "line_limit", "redacted"}
)

type bundleDocV1 struct {
	run             *runDoc
	sources         []*sourceDoc
	pathGiven       map[*sourceDoc]bool
	evidenceClass   string
	redactionStatus string
	digest          string
}

// ValidateV1 checks raw bytes against contract v1 and reports the first
// failing check, or the evidence digest on acceptance.
func ValidateV1(raw []byte) Result {
	root, b, f := checkV1(raw)
	if f != nil {
		return rejected(f)
	}
	digest := evidenceDigestFor(root, digestTagV1, evidenceMembersV1)
	if digest != b.digest {
		return rejected(failAt(CodeDigestMismatch, "/evidence_sha256", "recomputed evidence digest is %s", digest))
	}
	return Result{EvidenceSHA256: digest}
}

// DigestV1 runs every v1 check except the digest comparison and returns the
// evidence digest, so a producer can fill in evidence_sha256. On a failed
// check it returns "" and the rejection.
func DigestV1(raw []byte) (string, Result) {
	root, _, f := checkV1(raw)
	if f != nil {
		return "", rejected(f)
	}
	return evidenceDigestFor(root, digestTagV1, evidenceMembersV1), Result{}
}

func checkV1(raw []byte) (*value, *bundleDocV1, *failure) {
	if len(raw) > MaxInputBytes {
		return nil, nil, failAt(CodeInputTooLarge, "", "input is %d bytes; the limit is %d", len(raw), MaxInputBytes)
	}
	if !utf8.Valid(raw) {
		return nil, nil, failAt(CodeInvalidUTF8, "", "input is not well-formed UTF-8")
	}
	root, f := parseStrict(raw)
	if f != nil {
		return nil, nil, f
	}
	if f := findEvaluatorField(root, ""); f != nil {
		return nil, nil, f
	}
	b, f := checkBundleV1(root)
	if f != nil {
		return nil, nil, f
	}
	if f := crossCheckV1(b); f != nil {
		return nil, nil, f
	}
	return root, b, nil
}

// hasControlV1 reports U+0000-U+001F, U+007F or U+0080-U+009F; tab is
// allowed when allowTab is set.
func hasControlV1(s string, allowTab bool) bool {
	for _, r := range s {
		if r == 0x7f || (r >= 0x80 && r <= 0x9f) || (r < 0x20 && !(allowTab && r == '\t')) {
			return true
		}
	}
	return false
}

func (o *obj) displayV1(name string) (string, *failure) {
	s, f := o.str(name)
	if f != nil {
		return "", f
	}
	if len(s) < 1 || len(s) > 256 || hasControlV1(s, false) {
		return "", schemaErr(o.at(name), "must be 1-256 UTF-8 bytes without control characters")
	}
	return s, nil
}

func (o *obj) date(name string) (string, *failure) {
	s, f := o.str(name)
	if f != nil {
		return "", f
	}
	if len(s) != 10 || !validTimestamp(s+"T00:00:00Z") {
		return "", schemaErr(o.at(name), "%q is not a valid YYYY-MM-DD date", s)
	}
	return s, nil
}

func checkBundleV1(root *value) (*bundleDocV1, *failure) {
	o, f := object(root, "", bundleMembersV1, bundleMembersV1)
	if f != nil {
		return nil, f
	}
	b := &bundleDocV1{pathGiven: map[*sourceDoc]bool{}}
	if _, f := o.enum("schema", SchemaVersionV1); f != nil {
		return nil, f
	}
	if _, f := o.match("case_id", reCaseID); f != nil {
		return nil, f
	}
	if b.evidenceClass, f = o.enum("evidence_class", "collected_public", "simulated"); f != nil {
		return nil, f
	}
	if _, f := o.timestamp("created_at"); f != nil {
		return nil, f
	}
	col, f := o.child("collection", collectionMembersV1, collectionMembersV1)
	if f != nil {
		return nil, f
	}
	if _, f := col.match("tool", reID); f != nil {
		return nil, f
	}
	if _, f := col.date("api_version"); f != nil {
		return nil, f
	}
	if _, f := col.enum("metadata_authentication", "none"); f != nil {
		return nil, f
	}
	if b.redactionStatus, f = checkRedaction(o); f != nil {
		return nil, f
	}

	runs, f := o.array("runs")
	if f != nil {
		return nil, f
	}
	if len(runs) != 1 {
		return nil, schemaErr(o.at("runs"), "expected exactly 1 run, found %d", len(runs))
	}
	if b.run, f = checkRunV1(runs[0], o.at("runs")+"/0"); f != nil {
		return nil, f
	}

	sources, f := o.array("sources")
	if f != nil {
		return nil, f
	}
	if len(sources) > MaxSources {
		return nil, failAt(CodeTooManySources, o.at("sources"), "%d sources; the limit is %d", len(sources), MaxSources)
	}
	for i, sv := range sources {
		s, given, f := checkSourceV1(sv, o.at("sources")+"/"+strconv.Itoa(i))
		if f != nil {
			return nil, f
		}
		b.sources = append(b.sources, s)
		b.pathGiven[s] = given
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

func checkRedaction(bundle *obj) (string, *failure) {
	o, f := bundle.child("redaction", []string{"status", "rules"}, []string{"status"})
	if f != nil {
		return "", f
	}
	status, f := o.enum("status", "applied", "none")
	if f != nil {
		return "", f
	}
	if status == "none" {
		return status, o.onlyForm("status")
	}
	if f := o.onlyForm("status", "rules"); f != nil {
		return "", f
	}
	if f := o.require("rules"); f != nil {
		return "", f
	}
	if _, f := o.enum("rules", RedactionRulesV1); f != nil {
		return "", f
	}
	return status, nil
}

func checkRunV1(v *value, ptr string) (*runDoc, *failure) {
	o, f := object(v, ptr, runMembers, runMembers)
	if f != nil {
		return nil, f
	}
	r := &runDoc{ptr: ptr}
	if r.role, f = o.enum("role", "failed"); f != nil {
		return nil, f
	}
	repo, f := o.child("repository", repositoryMembersV1, repositoryMembersV1)
	if f != nil {
		return nil, f
	}
	if r.repoID, f = repo.integer("id", 1); f != nil {
		return nil, f
	}
	if r.repoName, f = repo.match("full_name", reRepoName); f != nil {
		return nil, f
	}
	if _, f = repo.enum("visibility", "public"); f != nil {
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
	if _, f = job.displayV1("name"); f != nil {
		return nil, f
	}
	if _, f = job.enum("conclusion", "failure"); f != nil {
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

	checkout, f := checkCheckoutWith(o, checkoutReasonsV1)
	if f != nil {
		return nil, f
	}
	r.spanLists = append(r.spanLists, checkout)
	matrix, hasMatrix, f := checkMatrixWith(o, matrixReasonsV1, (*obj).displayV1)
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

	if completed < started {
		return nil, schemaErr(job.at("completed_at"), "completed_at is earlier than started_at")
	}
	r.jobCompleted = completed
	return r, nil
}

// checkSourceV1 checks one source; pathGiven reports whether a path member
// was present.
func checkSourceV1(v *value, ptr string) (s *sourceDoc, pathGiven bool, f *failure) {
	o, f := object(v, ptr, sourceMembersV1, []string{"id", "kind", "run_role", "status"})
	if f != nil {
		return nil, false, f
	}
	s = &sourceDoc{ptr: ptr}
	if s.id, f = o.match("id", reID); f != nil {
		return nil, false, f
	}
	if s.kind, f = o.enum("kind", requiredKinds...); f != nil {
		return nil, false, f
	}
	if s.runRole, f = o.enum("run_role", "failed"); f != nil {
		return nil, false, f
	}
	status, f := o.enum("status", "present", "missing")
	if f != nil {
		return nil, false, f
	}
	s.present = status == "present"

	if s.kind == "job_log" {
		for _, name := range []string{"path", "revision"} {
			if o.has(name) {
				return nil, false, schemaErr(o.at(name), "%s is not allowed for a job_log source", name)
			}
		}
	} else {
		if s.present || o.has("path") {
			if s.path, f = o.str("path"); f != nil {
				return nil, false, f
			}
			pathGiven = true
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
				return nil, false, schemaErr(o.at("path"), "%q is not a valid %s path", s.path, s.kind)
			}
		}
		if s.present {
			if _, f = o.match("revision", reSHA); f != nil {
				return nil, false, f
			}
		} else if o.has("revision") {
			return nil, false, schemaErr(o.at("revision"), "revision is not allowed for a missing source")
		}
	}

	if !s.present {
		if _, f := o.enum("missing_reason", missingReasonsV1...); f != nil {
			return nil, false, f
		}
		for _, name := range presentOnlyV1 {
			if o.has(name) {
				return nil, false, schemaErr(o.at(name), "%s is not allowed for a missing source", name)
			}
		}
		return s, pathGiven, nil
	}

	if o.has("missing_reason") {
		return nil, false, schemaErr(o.at("missing_reason"), "missing_reason is not allowed for a present source")
	}
	if _, f = o.enum("extent", "complete", "prefix", "partial"); f != nil {
		return nil, false, f
	}
	if _, f = o.integer("received_bytes", 0); f != nil {
		return nil, false, f
	}
	if _, f = o.match("received_sha256", reDigest); f != nil {
		return nil, false, f
	}
	if _, f = o.enum("authentication", "none", "gh_cli"); f != nil {
		return nil, false, f
	}
	if s.lineCount, f = o.integer("line_count", 0); f != nil {
		return nil, false, f
	}
	if _, f = o.integer("redactions", 0); f != nil {
		return nil, false, f
	}
	lines, f := o.array("lines")
	if f != nil {
		return nil, false, f
	}
	if len(lines) > MaxLinesPerSource {
		return nil, false, failAt(CodeTooManyLines, o.at("lines"), "%d lines; the limit is %d", len(lines), MaxLinesPerSource)
	}
	for i, lv := range lines {
		ln, f := object(lv, o.at("lines")+"/"+strconv.Itoa(i), lineMembers, lineMembers)
		if f != nil {
			return nil, false, f
		}
		n, f := ln.integer("n", 0)
		if f != nil {
			return nil, false, f
		}
		text, f := ln.str("text")
		if f != nil {
			return nil, false, f
		}
		if len(text) > MaxLineBytes {
			return nil, false, failAt(CodeLineTooLong, ln.at("text"), "line text is %d UTF-8 bytes; the limit is %d", len(text), MaxLineBytes)
		}
		if hasControlV1(text, true) {
			return nil, false, schemaErr(ln.at("text"), "line text contains a control character other than tab")
		}
		s.lines = append(s.lines, n)
	}
	omitted, f := o.array("omitted")
	if f != nil {
		return nil, false, f
	}
	if len(omitted) > MaxOmittedPerSource {
		return nil, false, schemaErr(o.at("omitted"), "%d omitted ranges; the limit is %d", len(omitted), MaxOmittedPerSource)
	}
	for i, ov := range omitted {
		om, f := object(ov, o.at("omitted")+"/"+strconv.Itoa(i), omittedMembers, omittedMembers)
		if f != nil {
			return nil, false, f
		}
		start, f := om.integer("start", 0)
		if f != nil {
			return nil, false, f
		}
		end, f := om.integer("end", 0)
		if f != nil {
			return nil, false, f
		}
		reason, f := om.enum("reason", omittedReasonsV1...)
		if f != nil {
			return nil, false, f
		}
		s.omitted = append(s.omitted, rangeDoc{start: start, end: end, reason: reason})
	}
	return s, pathGiven, nil
}

func crossCheckV1(b *bundleDocV1) *failure {
	for _, kind := range requiredKinds {
		var found []*sourceDoc
		for _, s := range b.sources {
			if s.kind == kind {
				found = append(found, s)
			}
		}
		if len(found) == 0 {
			return failAt(CodeMissingSourceEntry, b.run.ptr, "the run has no %s source; list it with status missing if it was not obtained", kind)
		}
		if len(found) > 1 {
			return schemaErr(found[1].ptr+"/kind", "the run has more than one %s source", kind)
		}
	}
	for _, s := range b.sources {
		if s.kind == "workflow_file" && b.pathGiven[s] && s.path != b.run.workflowPath {
			return schemaErr(s.ptr+"/path", "workflow file path differs from the run's workflow path %q", b.run.workflowPath)
		}
	}
	if b.evidenceClass == "collected_public" && b.redactionStatus != "applied" {
		return schemaErr("/redaction/status", "a collected_public bundle must have redaction applied")
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
	for _, list := range b.run.spanLists {
		for _, sp := range list {
			if f := checkSpan(sp, b.run, byID); f != nil {
				return f
			}
		}
	}
	return nil
}
