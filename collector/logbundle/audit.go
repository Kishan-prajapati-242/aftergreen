package logbundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"aftergreen/collector/markers"
	"aftergreen/contracts/bundle"
)

// Selection audit: over every line of a log held in memory, count the lines
// matching the inspector's fixed patterns (contracts/inspection-v0.md section
// 3) and what a selection did with them. Lines are classified on their
// cleaned text, before redaction, so the totals do not depend on the
// selection. A matching included line counts as included when its bundle
// text, which the inspector reads, still matches. A match that exists only
// after redaction (a placeholder next to the text that follows it) is not
// counted, although the inspector would report it. The audit holds counts and
// capped lists of line numbers only, never text.

// AuditSchema names the audit's format.
const AuditSchema = "aftergreen.selection-audit.v0"

// AuditScope says what the counts mean, in an audit of the current
// producer's selection.
const AuditScope = "Counts of lines that match the fixed patterns of contracts/inspection-v0.md section 3 before redaction, and of what the current producer's selection did with them. Every pattern except step_header is also one of its selection signals, so such a line is omitted only by the line, byte or range budget (line_limit), by its length (line_too_long, or outside_selected_span for an over-long line that is not within 3 lines of another signal or among the first 5 or last 20 lines) or by redaction (redacted, or outside_selected_span when inline redaction removed the signal): the counts show what these cost, not how well the signals were chosen. They measure coverage of these known patterns only: not diagnosis accuracy, and not recall of all relevant evidence."

// SavedAuditScope says what the counts mean, in an audit of a saved
// bundle's selection.
const SavedAuditScope = "Counts of lines that match the fixed patterns of contracts/inspection-v0.md section 3 before redaction, and of what a saved bundle's selection did with them. That selection was made by the producer that wrote the bundle, whose selection signals may differ from the current producer's. hidden_by_inline_redaction counts included lines whose saved text no longer matches, whatever changed it. The counts measure coverage of these known patterns only: not diagnosis accuracy, and not recall of all relevant evidence."

// auditListCap is the number of line numbers listed per pattern and list.
const auditListCap = 20

// Audit is one selection's audit.
type Audit struct {
	Schema    string         `json:"schema"`
	Scope     string         `json:"scope"`
	LineCount int64          `json:"line_count"`
	Patterns  []PatternAudit `json:"patterns"`
}

// PatternAudit is one pattern's counts: Lines = Included +
// HiddenByInlineRedaction + the Omitted counts. The line lists hold the
// first 20 line numbers each, in line order; ListsTruncated says whether
// either list was cut.
type PatternAudit struct {
	Pattern  string `json:"pattern"`
	Lines    int    `json:"lines"`
	Included int    `json:"included"`
	// HiddenByInlineRedaction counts included lines whose match inline
	// redaction removed from the bundle text.
	HiddenByInlineRedaction int              `json:"hidden_by_inline_redaction"`
	Omitted                 map[string]int   `json:"omitted"`
	IncludedLines           []int64          `json:"included_lines"`
	OmittedLines            []AuditedOmitted `json:"omitted_lines"`
	ListsTruncated          bool             `json:"lists_truncated"`
}

// AuditedOmitted is an omitted line and its reason.
type AuditedOmitted struct {
	Line   int64  `json:"line"`
	Reason string `json:"reason"`
}

// auditPatterns are the audited patterns, in order: the error markers, then
// nonzero_exit and step_header.
func auditPatterns() []string {
	return append(append([]string{}, markers.Names...), "nonzero_exit", "step_header")
}

func classify(text string) map[string]bool {
	b := markers.Body(text)
	out := map[string]bool{}
	for _, m := range markers.ErrorMarkers(b) {
		out[m] = true
	}
	if _, ok := markers.ExitCode(b); ok {
		out["nonzero_exit"] = true
	}
	if markers.StepHeader(b) {
		out["step_header"] = true
	}
	return out
}

// newAudit classifies n lines. For line i+1, clean(i) is its cleaned text
// before redaction, fate(i) its omission reason ("" when included) and, for
// an included line, kept(i) its bundle text.
func newAudit(scope string, n int, clean, fate, kept func(int) string) *Audit {
	byName := map[string]*PatternAudit{}
	a := &Audit{Schema: AuditSchema, Scope: scope, LineCount: int64(n)}
	for _, p := range auditPatterns() {
		pa := PatternAudit{Pattern: p, Omitted: map[string]int{}, IncludedLines: []int64{}, OmittedLines: []AuditedOmitted{}}
		for _, r := range []string{"outside_selected_span", "line_too_long", "line_limit", "redacted"} {
			pa.Omitted[r] = 0
		}
		a.Patterns = append(a.Patterns, pa)
	}
	for i := range a.Patterns {
		byName[a.Patterns[i].Pattern] = &a.Patterns[i]
	}
	for i := 0; i < n; i++ {
		before, r := classify(clean(i)), fate(i)
		seen := map[string]bool{}
		if r == "" {
			seen = classify(kept(i))
		}
		for k := range a.Patterns {
			p := a.Patterns[k].Pattern
			if !before[p] {
				continue
			}
			pa := byName[p]
			pa.Lines++
			switch {
			case seen[p]:
				pa.Included++
				if len(pa.IncludedLines) < auditListCap {
					pa.IncludedLines = append(pa.IncludedLines, int64(i+1))
				} else {
					pa.ListsTruncated = true
				}
			case r == "":
				pa.HiddenByInlineRedaction++
			default:
				pa.Omitted[r]++
				if len(pa.OmittedLines) < auditListCap {
					pa.OmittedLines = append(pa.OmittedLines, AuditedOmitted{Line: int64(i + 1), Reason: r})
				} else {
					pa.ListsTruncated = true
				}
			}
		}
	}
	return a
}

// auditOf audits the producer's own selection.
func auditOf(lines []lineDoc, dec []decision) *Audit {
	return newAudit(AuditScope, len(lines),
		func(i int) string { return lines[i].clean },
		func(i int) string {
			if dec[i] == included {
				return ""
			}
			return reasonOf[dec[i]]
		},
		func(i int) string { return lines[i].text })
}

// ErrLogMismatch means the log bytes are not the bytes a bundle was built
// from: their byte count, hash or line count differs from the bundle's.
var ErrLogMismatch = errors.New("the log bytes are not the bytes the bundle was built from")

// ErrSavedLogMissing means a bundle has no job log to audit.
var ErrSavedLogMissing = errors.New("the saved bundle's job log is missing")

type auditJobLog struct {
	Kind           string `json:"kind"`
	Status         string `json:"status"`
	ReceivedBytes  int64  `json:"received_bytes"`
	ReceivedSHA256 string `json:"received_sha256"`
	LineCount      int64  `json:"line_count"`
	Lines          []struct {
		N    int64  `json:"n"`
		Text string `json:"text"`
	} `json:"lines"`
	Omitted []struct {
		Start  int64  `json:"start"`
		End    int64  `json:"end"`
		Reason string `json:"reason"`
	} `json:"omitted"`
}

func jobLogOfBundle(raw []byte) (*auditJobLog, error) {
	if v := bundle.ValidateV1(raw); !v.Accepted() {
		return nil, fmt.Errorf("not an accepted bundle v1 (%s)", v.Code)
	}
	var d struct {
		Sources []auditJobLog `json:"sources"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	for i := range d.Sources {
		if d.Sources[i].Kind == "job_log" {
			return &d.Sources[i], nil
		}
	}
	return nil, errors.New("no job log") // unreachable for an accepted bundle
}

// AuditBundle audits a saved bundle's selection against the log bytes it was
// built from, with SavedAuditScope. It returns ErrLogMismatch for any other
// bytes, so a saved bundle is never audited against a different log.
func AuditBundle(log, bundleRaw []byte) (*Audit, error) {
	job, err := jobLogOfBundle(bundleRaw)
	if err != nil {
		return nil, err
	}
	if job.Status != "present" {
		return nil, ErrSavedLogMissing
	}
	sum := sha256.Sum256(log)
	raw := splitLines(log)
	if job.ReceivedBytes != int64(len(log)) || job.ReceivedSHA256 != hex.EncodeToString(sum[:]) || job.LineCount != int64(len(raw)) {
		return nil, ErrLogMismatch
	}
	text := map[int64]string{}
	for _, l := range job.Lines {
		text[l.N] = l.Text
	}
	omitted := job.Omitted
	sort.Slice(omitted, func(a, b int) bool { return omitted[a].Start < omitted[b].Start })
	k := 0
	return newAudit(SavedAuditScope, len(raw),
		func(i int) string { return cleanLine(raw[i], i == 0) },
		func(i int) string {
			n := int64(i + 1)
			if _, ok := text[n]; ok {
				return ""
			}
			for k < len(omitted) && omitted[k].End < n { // lines are visited in order
				k++
			}
			return omitted[k].Reason // every line is included or omitted (bundle v1 section 4)
		},
		func(i int) string { return text[int64(i+1)] }), nil
}

// SameSelection reports whether two bundles include the same lines of their
// job logs and omit the rest in the same ranges, for the same reasons.
func SameSelection(a, b []byte) (bool, error) {
	ja, err := jobLogOfBundle(a)
	if err != nil {
		return false, err
	}
	jb, err := jobLogOfBundle(b)
	if err != nil {
		return false, err
	}
	if ja.Status != jb.Status || ja.LineCount != jb.LineCount || len(ja.Lines) != len(jb.Lines) || len(ja.Omitted) != len(jb.Omitted) {
		return false, nil
	}
	for i := range ja.Lines {
		if ja.Lines[i].N != jb.Lines[i].N {
			return false, nil
		}
	}
	for i := range ja.Omitted {
		if ja.Omitted[i] != jb.Omitted[i] {
			return false, nil
		}
	}
	return true, nil
}
