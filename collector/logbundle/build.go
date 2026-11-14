package logbundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"aftergreen/contracts/bundle"
)

// Input is what a collection established for one failed job, in the form
// the API returned it. Values are copied into the bundle as producer claims;
// nothing is inferred. HeadSHA is run metadata and never becomes a checkout.
type Input struct {
	RepoID           int64
	FullName         string
	Public           bool // the API stated "private": false
	WorkflowID       int64
	WorkflowPath     string
	RunID            int64
	RunAttempt       int64
	AttemptStartedAt string
	Event            string
	Branch           string
	HeadSHA          string
	JobID            int64
	JobName          string
	JobConclusion    string
	JobStartedAt     string
	JobCompletedAt   string
	JobLabels        []string
	Log              Log
}

// Log is the job-log request's outcome. Bytes are the received bytes, before
// any transform, held in memory only.
type Log struct {
	Obtained       bool
	Extent         string // complete, prefix or partial
	MissingReason  string // when not obtained
	Authentication string // none or gh_cli
	Bytes          []byte
	ReceivedBytes  int64
	SHA256         string
}

// Options sets the producer claims that are not in the evidence.
type Options struct {
	EvidenceClass string    // "collected_public" for a live collection, "simulated" for test data
	Tool          string    // collection.tool
	APIVersion    string    // collection.api_version: the REST API version requested
	CreatedAt     time.Time // created_at, truncated to the second
	// Audit adds a selection audit (audit.go) to the summary: counts and
	// capped line numbers only.
	Audit bool

	noRedaction bool // tests only: a negative control with redaction off
	noStepSpans bool // tests only: the selection without step spans, for comparison
}

// Summary describes a built bundle with counts only, never its text.
type Summary struct {
	Bytes          int        `json:"bytes"`
	EvidenceSHA256 string     `json:"evidence_sha256"`
	EvidenceClass  string     `json:"evidence_class"`
	JobLog         LogSummary `json:"job_log"`
	MissingSources []string   `json:"missing_sources"`
	Unresolved     []string   `json:"unresolved"`
	// Audit is set when Options.Audit is and the log was obtained.
	Audit *Audit `json:"selection_audit,omitempty"`
}

// LogSummary counts what happened to the job log's lines.
type LogSummary struct {
	Status         string           `json:"status"` // present or missing
	MissingReason  string           `json:"missing_reason,omitempty"`
	Extent         string           `json:"extent,omitempty"`
	Authentication string           `json:"authentication,omitempty"`
	ReceivedBytes  int64            `json:"received_bytes"`
	LineCount      int64            `json:"line_count"`
	IncludedLines  int              `json:"included_lines"`
	OmittedLines   map[string]int64 `json:"omitted_lines"`  // by reason
	OmittedRanges  int              `json:"omitted_ranges"` // entries in the bundle
	Redactions     map[string]int   `json:"redactions"`     // inline replacements in the included lines, by rule
	// DroppedToFitRanges counts selected lines left out, as line_limit, so
	// that the exact reasons fit the 501-range limit.
	DroppedToFitRanges int `json:"dropped_to_fit_ranges"`
}

// ErrIncomplete wraps every reason a bundle cannot be built from the input.
var ErrIncomplete = errors.New("incomplete")

// ErrRangeLimit means that, at none of the line budgets Build tries
// (lineBudgets), the selection lists every omitted line under its exact
// reason within both bundle v1's 501 omitted ranges and its 131,072 bytes.
// The budgets are at most 1,024 bytes apart, so a narrow fitting window
// between two of them can be missed. It is returned only when even the selection with no
// included line needs more than 501 ranges, since that one always fits the
// size limit once the metadata is valid. No bundle is built: a reason is
// never replaced to make the map fit. It wraps ErrIncomplete.
var ErrRangeLimit = fmt.Errorf("%w: at no line budget tried does a selection list every omission reason exactly within both %d omitted ranges and %d bytes", ErrIncomplete, maxOmitted, bundle.MaxInputBytes)

var labelRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

const (
	startBudget = 110_000 // bytes of encoded line objects, tried first
	budgetStep  = 1_024   // then smaller budgets by this step, then 0
)

// lineBudgets lists the line budgets Build tries, largest first: startBudget,
// then budgetStep less each time while still positive, then 0. Each value
// appears once; 110,000 ends 432, 0.
func lineBudgets() []int {
	var out []int
	for b := startBudget; b > 0; b -= budgetStep {
		out = append(out, b)
	}
	return append(out, 0)
}

// Build returns a validated v1 bundle and its summary. An error wrapping
// ErrIncomplete means the input cannot be represented; no bundle is returned.
func Build(in Input, opt Options) ([]byte, *Summary, error) {
	switch {
	case opt.EvidenceClass != "collected_public" && opt.EvidenceClass != "simulated":
		return nil, nil, errors.New("the evidence class must be collected_public or simulated")
	case opt.CreatedAt.IsZero():
		return nil, nil, errors.New("the creation time is not set")
	case !in.Public:
		return nil, nil, fmt.Errorf("%w: the repository was not shown to be public", ErrIncomplete)
	}
	sum := &Summary{EvidenceClass: opt.EvidenceClass, MissingSources: []string{}, Unresolved: []string{}}
	labels := []string{}
	for _, l := range in.JobLabels {
		if labelRE.MatchString(l) && len(labels) < 10 {
			labels = append(labels, l)
		}
	}
	if dropped := len(in.JobLabels) - len(labels); dropped > 0 {
		sum.Unresolved = append(sum.Unresolved, fmt.Sprintf("runner.labels: %d of the job's labels did not fit the bundle's label rule and were left out", dropped))
	}
	sum.Unresolved = append(sum.Unresolved,
		"checkout: unresolved (workflow_not_collected); head_sha is run metadata, not a checkout",
		"matrix: unresolved (workflow_not_collected)",
		"runner.os and runner.arch: unknown; the labels are the job's labels from the API")

	logSrc, lines, err := prepareLog(in.Log, opt)
	if err != nil {
		return nil, nil, err
	}
	sum.JobLog = LogSummary{Status: "missing", MissingReason: in.Log.MissingReason, OmittedLines: map[string]int64{}, Redactions: map[string]int{}}
	if in.Log.Obtained {
		sum.JobLog.Status, sum.JobLog.MissingReason = "present", ""
		sum.JobLog.Extent, sum.JobLog.Authentication = in.Log.Extent, in.Log.Authentication
		sum.JobLog.ReceivedBytes, sum.JobLog.LineCount = in.Log.ReceivedBytes, int64(len(lines))
	} else {
		sum.MissingSources = append(sum.MissingSources, "failed.job_log (job_log): "+in.Log.MissingReason)
	}
	sum.MissingSources = append(sum.MissingSources,
		"failed.lockfile (lockfile): not_collected", "failed.manifest (manifest): not_collected", "failed.workflow (workflow_file): not_collected")

	doc := bundleJSON{
		Schema:        bundle.SchemaVersionV1,
		CaseID:        caseID(in),
		EvidenceClass: opt.EvidenceClass,
		CreatedAt:     opt.CreatedAt.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z"),
		Collection:    collectionJSON{Tool: opt.Tool, APIVersion: opt.APIVersion, MetadataAuthentication: "none"},
		Redaction:     redactionJSON{Status: "applied", Rules: RulesID},
		Runs: []runJSON{{
			Role:             "failed",
			Repository:       repositoryJSON{ID: in.RepoID, FullName: in.FullName, Visibility: "public"},
			Workflow:         workflowJSON{ID: in.WorkflowID, Path: in.WorkflowPath},
			RunID:            in.RunID,
			RunAttempt:       in.RunAttempt,
			AttemptStartedAt: in.AttemptStartedAt,
			Event:            in.Event,
			Branch:           in.Branch,
			HeadSHA:          in.HeadSHA,
			Job:              jobJSON{ID: in.JobID, Name: in.JobName, Conclusion: in.JobConclusion, StartedAt: in.JobStartedAt, CompletedAt: in.JobCompletedAt},
			Checkout:         unresolvedJSON{Status: "unresolved", Reason: "workflow_not_collected", Evidence: []spanJSON{}},
			Matrix:           unresolvedJSON{Status: "unresolved", Reason: "workflow_not_collected", Evidence: []spanJSON{}},
			Runner:           runnerJSON{OS: "unknown", Arch: "unknown", Labels: labels, Evidence: []spanJSON{}},
		}},
		EvidenceSHA256: zeroDigest,
	}
	if opt.noRedaction {
		doc.Redaction = redactionJSON{Status: "none"}
	}
	workflowPath := in.WorkflowPath
	others := []sourceJSON{
		{ID: "failed.lockfile", Kind: "lockfile", RunRole: "failed", Status: "missing", MissingReason: "not_collected"},
		{ID: "failed.manifest", Kind: "manifest", RunRole: "failed", Status: "missing", MissingReason: "not_collected"},
		{ID: "failed.workflow", Kind: "workflow_file", RunRole: "failed", Status: "missing", Path: &workflowPath, MissingReason: "not_collected"},
	}

	// The metadata is checked first: the bundle with the job log's own
	// collection fields (status and missing reason, or extent, received bytes,
	// hash and authentication) but no line. A metadata problem is then reported
	// as one, never as a line-selection limit. Valid metadata is small (display
	// strings are at most 256 bytes), so a selection with no line always fits
	// the size limit.
	pjob := logSrc
	if in.Log.Obtained {
		zero, none := int64(0), 0
		noLines, noRanges := []lineJSON{}, []omittedJSON{}
		pjob.LineCount, pjob.Redactions, pjob.Lines, pjob.Omitted = &zero, &none, &noLines, &noRanges
	}
	probe := doc
	probe.Sources = append([]sourceJSON{pjob}, others...)
	if raw, err := encode(probe); err != nil {
		return nil, nil, err
	} else if _, r := bundle.DigestV1(raw); !r.Accepted() {
		return nil, nil, metadataError(r)
	}

	var rk ranking
	if in.Log.Obtained {
		rk = rankLines(lines)
	}
	var chosen []decision // the selection of the bundle being built
	for _, budget := range lineBudgets() {
		job := logSrc
		dropped := 0
		if in.Log.Obtained {
			dec := rk.admit(budget)
			var ok bool
			if dropped, ok = fitRanges(dec, rk.rank); !ok {
				continue // the exact reasons need more ranges with this selection: try a smaller one
			}
			if job, err = presentLog(logSrc, lines, dec, sum); err != nil {
				return nil, nil, err
			}
			sum.JobLog.DroppedToFitRanges = dropped
			chosen = dec
		}
		doc.Sources = append([]sourceJSON{job}, others...)
		doc.EvidenceSHA256 = zeroDigest
		raw, err := encode(doc)
		if err != nil {
			return nil, nil, err
		}
		if len(raw) > bundle.MaxInputBytes {
			continue // fewer lines next time
		}
		// This selection fits; step spans are added to it if they fit too.
		if in.Log.Obtained && dropped == 0 && !opt.noStepSpans && rk.addStepSpans(lines, chosen, budget, len(raw)) > 0 {
			if job, err = presentLog(logSrc, lines, chosen, sum); err != nil {
				return nil, nil, err
			}
			doc.Sources = append([]sourceJSON{job}, others...)
			if raw, err = encode(doc); err != nil {
				return nil, nil, err
			}
			if len(raw) > bundle.MaxInputBytes {
				return nil, nil, fmt.Errorf("the producer's step spans made a bundle of %d bytes, over %d; this is a defect", len(raw), bundle.MaxInputBytes) // addStepSpans bounds the size
			}
		}
		digest, r := bundle.DigestV1(raw)
		if !r.Accepted() {
			if producerBuilt(r.Pointer) {
				return nil, nil, fmt.Errorf("the producer built an invalid job log (%s at %s); this is a defect", r.Code, r.Pointer)
			}
			return nil, nil, metadataError(r)
		}
		doc.EvidenceSHA256 = digest
		if raw, err = encode(doc); err != nil {
			return nil, nil, err
		}
		if v := bundle.ValidateV1(raw); !v.Accepted() || v.EvidenceSHA256 != digest {
			return nil, nil, fmt.Errorf("the built bundle failed validation: %s at %s", v.Code, v.Pointer)
		}
		sum.Bytes, sum.EvidenceSHA256 = len(raw), digest
		if opt.Audit && in.Log.Obtained {
			sum.Audit = auditOf(lines, chosen) // once, for the selection returned
		}
		return raw, sum, nil
	}
	// Every budget failed. The last one tried, 0, includes no line, and with
	// valid metadata and at most 501 ranges such a bundle is far under the
	// size limit (about 45 KB at most), so its exact reasons needed more than
	// 501 ranges.
	return nil, nil, ErrRangeLimit
}

const zeroDigest = "0000000000000000000000000000000000000000000000000000000000000000"

// metadataError reports collected metadata that bundle v1 cannot hold.
func metadataError(r bundle.Result) error {
	if r.Pointer == "" {
		return fmt.Errorf("%w: the collected metadata cannot be represented in bundle v1 (%s)", ErrIncomplete, r.Code)
	}
	return fmt.Errorf("%w: the collected metadata cannot be represented in bundle v1 (%s at %s)", ErrIncomplete, r.Code, r.Pointer)
}

// producerBuilt reports whether a rejection points at the job log's line
// map, which the producer builds itself, or at the whole input. A rejection
// there is a defect, not missing or unrepresentable input.
func producerBuilt(pointer string) bool {
	if pointer == "" {
		return true
	}
	for _, m := range []string{"lines", "omitted", "line_count", "redactions"} {
		if p := "/sources/0/" + m; pointer == p || strings.HasPrefix(pointer, p+"/") {
			return true
		}
	}
	return false
}

// caseID is neutral: a hash of the identifiers, with no hint of a diagnosis.
func caseID(in Input) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s/%d/%d/%d", in.FullName, in.RunID, in.RunAttempt, in.JobID)))
	return "gh-" + hex.EncodeToString(h[:10])
}

// prepareLog numbers, cleans and redacts the received log, or describes the
// missing log.
func prepareLog(lg Log, opt Options) (sourceJSON, []lineDoc, error) {
	src := sourceJSON{ID: "failed.job_log", Kind: "job_log", RunRole: "failed"}
	if !lg.Obtained {
		src.Status, src.MissingReason = "missing", lg.MissingReason
		return src, nil, nil
	}
	sum := sha256.Sum256(lg.Bytes)
	if int64(len(lg.Bytes)) != lg.ReceivedBytes || hex.EncodeToString(sum[:]) != lg.SHA256 {
		return src, nil, errors.New("the log bytes do not match the received byte count and hash")
	}
	raw := splitLines(lg.Bytes)
	lines := make([]lineDoc, len(raw))
	texts := make([]string, len(raw)) // cleaned
	plain := make([]string, len(raw)) // controls removed, escape sequences' printable bytes kept
	for i, b := range raw {
		texts[i], plain[i] = cleanLine(b, i == 0), plainLine(b, i == 0)
	}
	var withheld []bool
	if !opt.noRedaction {
		// Key markers are looked for in both forms, so that removing an
		// escape sequence cannot hide one.
		withheld = keyBlocks(texts)
		for i, in := range keyBlocks(plain) {
			withheld[i] = withheld[i] || in
		}
	}
	for i, t := range texts {
		// A withheld line, or one too long to include, is never scanned.
		l := lineDoc{text: t, clean: t, withheld: withheld != nil && withheld[i]}
		if !l.withheld && len(t) <= maxLineBytes && !opt.noRedaction {
			l.text, l.counts = redactLine(t)
			if hidden(t, plain[i]) {
				l.text, l.counts, l.withheld = t, nil, true
			}
		}
		l.tooLong = !l.withheld && len(l.text) > maxLineBytes
		if !validText(l.text) {
			return src, nil, fmt.Errorf("line %d is not valid text after cleaning", i+1) // unreachable: cleanLine removes every control
		}
		lines[i] = l
	}
	received := lg.ReceivedBytes
	src.Status, src.Extent, src.ReceivedBytes, src.ReceivedSHA256 = "present", lg.Extent, &received, lg.SHA256
	src.Authentication = lg.Authentication
	return src, lines, nil
}

// presentLog fills in the job log's lines and omitted ranges for one
// selection, and the summary's counts.
func presentLog(src sourceJSON, lines []lineDoc, dec []decision, sum *Summary) (sourceJSON, error) {
	ranges := omittedRanges(dec)
	if len(ranges) > maxOmitted {
		return src, fmt.Errorf("the producer made %d omitted ranges, more than %d; this is a defect", len(ranges), maxOmitted) // fitRanges prevents it
	}
	count := int64(len(lines))
	src.LineCount = &count
	kept := []lineJSON{}
	redactions := 0
	ls := &sum.JobLog
	ls.OmittedLines, ls.Redactions = map[string]int64{}, map[string]int{}
	for i, l := range lines {
		if dec[i] != included {
			ls.OmittedLines[reasonOf[dec[i]]]++
			continue
		}
		kept = append(kept, lineJSON{N: int64(i + 1), Text: l.text})
		for rule, n := range l.counts {
			ls.Redactions[rule] += n
			redactions += n
		}
	}
	src.Redactions = &redactions
	src.Lines = &kept
	if ranges == nil {
		ranges = []omittedJSON{}
	}
	src.Omitted = &ranges
	ls.IncludedLines, ls.OmittedRanges = len(kept), len(ranges)
	return src, nil
}

func encode(doc bundleJSON) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// The v1 document, members in contract order.

type bundleJSON struct {
	Schema         string         `json:"schema"`
	CaseID         string         `json:"case_id"`
	EvidenceClass  string         `json:"evidence_class"`
	CreatedAt      string         `json:"created_at"`
	Collection     collectionJSON `json:"collection"`
	Redaction      redactionJSON  `json:"redaction"`
	Runs           []runJSON      `json:"runs"`
	Sources        []sourceJSON   `json:"sources"`
	EvidenceSHA256 string         `json:"evidence_sha256"`
}

type collectionJSON struct {
	Tool                   string `json:"tool"`
	APIVersion             string `json:"api_version"`
	MetadataAuthentication string `json:"metadata_authentication"`
}

type redactionJSON struct {
	Status string `json:"status"`
	Rules  string `json:"rules,omitempty"`
}

type runJSON struct {
	Role             string         `json:"role"`
	Repository       repositoryJSON `json:"repository"`
	Workflow         workflowJSON   `json:"workflow"`
	RunID            int64          `json:"run_id"`
	RunAttempt       int64          `json:"run_attempt"`
	AttemptStartedAt string         `json:"attempt_started_at"`
	Event            string         `json:"event"`
	Branch           string         `json:"branch"`
	HeadSHA          string         `json:"head_sha"`
	Job              jobJSON        `json:"job"`
	Checkout         unresolvedJSON `json:"checkout"`
	Matrix           unresolvedJSON `json:"matrix"`
	Runner           runnerJSON     `json:"runner"`
}

type repositoryJSON struct {
	ID         int64  `json:"id"`
	FullName   string `json:"full_name"`
	Visibility string `json:"visibility"`
}

type workflowJSON struct {
	ID   int64  `json:"id"`
	Path string `json:"path"`
}

type jobJSON struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Conclusion  string `json:"conclusion"`
	StartedAt   string `json:"started_at"`
	CompletedAt string `json:"completed_at"`
}

type unresolvedJSON struct {
	Status   string     `json:"status"`
	Reason   string     `json:"reason"`
	Evidence []spanJSON `json:"evidence"`
}

type spanJSON struct {
	SourceID string `json:"source_id"`
	Start    int64  `json:"start"`
	End      int64  `json:"end"`
}

type runnerJSON struct {
	OS       string     `json:"os"`
	Arch     string     `json:"arch"`
	Labels   []string   `json:"labels"`
	Evidence []spanJSON `json:"evidence"`
}

type sourceJSON struct {
	ID             string         `json:"id"`
	Kind           string         `json:"kind"`
	RunRole        string         `json:"run_role"`
	Status         string         `json:"status"`
	Path           *string        `json:"path,omitempty"`
	MissingReason  string         `json:"missing_reason,omitempty"`
	Extent         string         `json:"extent,omitempty"`
	ReceivedBytes  *int64         `json:"received_bytes,omitempty"`
	ReceivedSHA256 string         `json:"received_sha256,omitempty"`
	Authentication string         `json:"authentication,omitempty"`
	LineCount      *int64         `json:"line_count,omitempty"`
	Redactions     *int           `json:"redactions,omitempty"`
	Lines          *[]lineJSON    `json:"lines,omitempty"`
	Omitted        *[]omittedJSON `json:"omitted,omitempty"`
}

type lineJSON struct {
	N    int64  `json:"n"`
	Text string `json:"text"`
}
